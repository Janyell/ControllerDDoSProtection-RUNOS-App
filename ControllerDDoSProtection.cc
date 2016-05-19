#include "ControllerDDoSProtection.hh"
#include "AppObject.hh"
#include "FluidUtils.hh"

REGISTER_APPLICATION(ControllerDDoSProtection, {"controller", "switch-manager", ""})

bool ControllerDDoSProtection::isDDoS = false;
ControllerDDoSProtection::Users ControllerDDoSProtection::users;
ControllerDDoSProtection::Params ControllerDDoSProtection::params;
ControllerDDoSProtection::Users::Statistics ControllerDDoSProtection::Users::statistics;


// ControllerDDoSProtection
void ControllerDDoSProtection::init(Loader *loader, const Config& config)
{
    LOG(INFO) << "ControllerDDoSProtection::init()";
    detectDDoSTimer = new QTimer(this);
    Controller* ctrl = Controller::get(loader);
    ctrl->registerHandler(this);
    params.init();

    QObject::connect(detectDDoSTimer, SIGNAL(timeout()), this, SLOT(detectDDoSTimeout()));
    QObject::connect(updateValidAvgConnTimer, SIGNAL(timeout()), this, SLOT(updateValidAvgConnTimeout()));
    QObject::connect(clearInvalidUsersTimer, SIGNAL(timeout()), this, SLOT(clearInvalidUsersTimeout()));
    QObject::connect(this, SIGNAL(UsersTypeChanged(IPAddressV4)), this, SLOT(getUsersStatistics(IPAddressV4)));

    pdescr = Controller::get(loader)->registerStaticTransaction(this);
    QObject::connect(pdescr, &OFTransaction::response,
                     this, &ControllerDDoSProtection::usersStatisticsArrived);

    QObject::connect(pdescr, &OFTransaction::error,
    [](OFConnection* conn, std::shared_ptr<OFMsgUnion> msg)
    {
        of13::Error& error = msg->error;
        LOG(ERROR) << "Switch reports error for OFPT_MULTIPART_REQUEST: "
            << "type " << (int) error.type() << " code " << error.code();
        // Send request again
        conn->send(error.data(), error.data_len());
    });
}

void ControllerDDoSProtection::startUp(Loader *)
{
    LOG(INFO) << "ControllerDDoSProtection::startUp()";
    detectDDoSTimer->start(DETECT_DDOS_TIMER_INTERVAL * 1000);
}

void ControllerDDoSProtection::detectDDoSTimeout()
{
//    LOG(INFO) << "ControllerDDoSProtection::detectDDoSTimeout()";
    users.update();
    Users::Statistics statistics = users.getStatistics();
    bool isDetectedDDoS = statistics.handle();
    if (isDetectedDDoS) {
        isDDoS = true;
    }
    users.resetStatistics();
}

void ControllerDDoSProtection::updateValidAvgConnTimeout()
{
    LOG(INFO) << "ControllerDDoSProtection::updateValidAvgConnTimeout()";
    params.updateValidAvgConnNumber();
}

void ControllerDDoSProtection::clearInvalidUsersTimeout()
{
    LOG(INFO) << "ControllerDDoSProtection::clearInvalidUsersTimeout()";
    /* todo */
}

void ControllerDDoSProtection::getUsersStatistics (IPAddressV4 ipAddr, OFConnection *ofconn)
{
    LOG(INFO) << "ControllerDDoSProtection::getUsersStatistics(" << AppObject::uint32_t_ip_to_string(ipAddr) << ")";
    of13::MultipartRequestFlow req;
    req.out_port(of13::OFPP_ANY);
    req.out_group(of13::OFPG_ANY);
    req.add_oxm_field(new of13::IPv4Src(IPAddress(ipAddr)));
    pdescr->request(ofconn, &req);
}

void ControllerDDoSProtection::usersStatisticsArrived(OFConnection *ofconn, std::shared_ptr<OFMsgUnion> reply)
{
    auto type = reply->base()->type();
    if (type != of13::OFPT_MULTIPART_REPLY) {
        LOG(ERROR) << "Unexpected response of type " << type
                << " received, expected OFPT_MULTIPART_REPLY";
        return;
    }

    of13::MultipartReplyFlow stats = reply->multipartReplyFlow;
    std::vector<of13::FlowStats> s = stats.flow_stats();

    size_t invalidFlowsNumber = 0;
    size_t minPacketNumber = 0;

    if (s.size() == 0) return;

    of13::Match match = s[0].match();
    IPAddress ipAddr = s[0].match().ipv4_src()->value();
    IPAddressV4 ipAddrV4 = ipAddr.getIPv4();

    LOG(INFO) << "ControllerDDoSProtection::usersStatisticsArrived(" << AppObject::uint32_t_ip_to_string(ipAddrV4) << ")";

    for (auto& i : s)
    {
        uint64_t packetNumber = i.packet_count();
        minPacketNumber = std::min(packetNumber, minPacketNumber);
        if (params.isInvalidPacketNumber(packetNumber))
        {
            ++invalidFlowsNumber;
        }
    }
    if (invalidFlowsNumber / (float) s.size() > INVALID_FLOW_PERCENT) {
        std::map<IPAddressV4, Users::ValidUsersParams>::iterator validUser;
        std::map<IPAddressV4, Users::InvalidUsersParams>::iterator invalidUser;
        Users::UsersTypes type = users.get(ipAddrV4, validUser, invalidUser);
        switch (type)
        {
        case Users::UsersTypes::Invalid:
            invalidUser->second.check();
            break;
        case Users::UsersTypes::Valid:
            users.invalidate(validUser);
            break;
        case Users::UsersTypes::Unknown:
            throw Users::UsersExceptionTypes::IsUnknown;
        }
        detectDDoSTimeout();
    }
}

// ControllerDDoSProtection::Handler
OFMessageHandler::Action ControllerDDoSProtection::Handler::processMiss(OFConnection* ofconn, Flow* flow)
{
    uint16_t ethType = flow->loadEthType();
    if (ethType != IPv4_TYPE)
        return Continue;

    IPAddress srcIPAddr = flow->loadIPv4Src();
    IPAddressV4 srcIPAddrV4 = srcIPAddr.getIPv4();

    IPAddress dstIPAddr = flow->loadIPv4Dst();
    IPAddressV4 dstIPAddrV4 = dstIPAddr.getIPv4();

    if (srcIPAddrV4 == IPAddress("0.0.0.0").getIPv4() || dstIPAddrV4 == IPAddress("0.0.0.0").getIPv4())
    {
        return Continue;
    }

    LOG(INFO) << "ControllerDDoSProtection::Handler::processMiss()";
    LOG(INFO) << AppObject::uint32_t_ip_to_string(srcIPAddrV4) << "\t-->\t" <<AppObject::uint32_t_ip_to_string(dstIPAddrV4);

    std::map<IPAddressV4, Users::ValidUsersParams>::iterator validUser;
    std::map<IPAddressV4, Users::InvalidUsersParams>::iterator invalidUser;
    Users::UsersTypes type = users.get(srcIPAddrV4, validUser, invalidUser);

    switch (type)
    {
    case Users::UsersTypes::Valid:
        try
        {
            validUser->second.increaseConnCounter();
        }
        catch (Users::UsersExceptionTypes e)
        {
            emit app->UsersTypeChanged(srcIPAddrV4, ofconn);
//            return Stop;
        }
        if (validUser->second.typeIsChecked())
        {
            FlowHandler::setNormalTimeouts(flow);
        }
        else
        {
            FlowHandler::setShortTimeouts(flow);
        }
        break;
    case Users::UsersTypes::Invalid:
    {
        try
        {
            invalidUser->second.increaseConnCounter();
        }
        catch (Users::UsersExceptionTypes e)
        {
            emit app->UsersTypeChanged(srcIPAddrV4, ofconn);
        }
        Users::InvalidUsersParams::InvalidUsersTypes invalidType = (invalidUser->second).getType();
        bool invalidTypeIsChecked = (invalidUser->second).typeIsChecked();
        if (invalidType == Users::InvalidUsersParams::InvalidUsersTypes::Malicious
                && invalidTypeIsChecked == 1)
        {
            flow->setFlags(Flow::Disposable);
            return Stop;
        }
        if (isDDoS)
        {
            FlowHandler::setShortTimeouts(flow);
        }
        else
        {
            FlowHandler::setNormalTimeouts(flow);
        }
        break;
    }
    case Users::UsersTypes::Unknown:
        users.insert(srcIPAddrV4);
        if (isDDoS)
        {
            FlowHandler::setShortTimeouts(flow);
        }
        else
        {
            FlowHandler::setNormalTimeouts(flow);
        }
        break;
    }
    return Continue;
}


// ControllerDDoSProtection::Users
ControllerDDoSProtection::Users::UsersTypes
ControllerDDoSProtection::Users::get (IPAddressV4 ipAddr,
                                      std::map<IPAddressV4, ValidUsersParams>::iterator &validUser,
                                      std::map<IPAddressV4, InvalidUsersParams>::iterator &invalidUser)
{
    LOG(INFO) << "ControllerDDoSProtection::Users::get(" << AppObject::uint32_t_ip_to_string(ipAddr) << ")";
    std::map<IPAddressV4, ValidUsersParams>::iterator itValidUser = validUsers.find(ipAddr);
    if (itValidUser != validUsers.end())
    {
        validUser = itValidUser;
        return UsersTypes::Valid;
    }

    std::map<IPAddressV4, InvalidUsersParams>::iterator itInvalidUser = invalidUsers.find(ipAddr);
    if (itInvalidUser != invalidUsers.end())
    {
        invalidUser = itInvalidUser;
        return UsersTypes::Invalid;
    }

    return UsersTypes::Unknown;
}

void ControllerDDoSProtection::Users::insert (IPAddressV4 ipAddr)
{
    LOG(INFO) << "ControllerDDoSProtection::Users::insert(" << AppObject::uint32_t_ip_to_string(ipAddr) << ")";
    InvalidUsersParams invalidUsersParams;
    invalidUsers.insert (std::pair <IPAddressV4, InvalidUsersParams> (ipAddr, invalidUsersParams));
    statistics.update(Statistics::Actions::Insert,
                      InvalidUsersParams::InvalidUsersTypes::None,
                      InvalidUsersParams::InvalidUsersTypes::DDoS);
}

void ControllerDDoSProtection::Users::invalidate(std::map<IPAddressV4, ValidUsersParams>::iterator it)
{
    InvalidUsersParams invalidUsersParams(it->second);
    invalidUsers.insert(std::pair <IPAddressV4, InvalidUsersParams> (it->first, invalidUsersParams));
    validUsers.erase(it);
    statistics.update(Statistics::Actions::Insert,
                      InvalidUsersParams::InvalidUsersTypes::None,
                      InvalidUsersParams::InvalidUsersTypes::Malicious);
}

void ControllerDDoSProtection::Users::update()
{
    for (auto it = invalidUsers.begin(), end = invalidUsers.end(); it != end; ++it)
    {
        if ((it->second).isObsolete())
        {
            invalidUsers.erase(it);
            statistics.update(Statistics::Actions::Remove, (it->second).getType(), InvalidUsersParams::InvalidUsersTypes::None);
        }
    }
}


// ControllerDDoSProtection::Users::ValidUsersParams
void ControllerDDoSProtection::Users::ValidUsersParams::checkType()
{
    // Valid -> Malicious
    if (params.isInvalidConnNumber(connCounter)
            || (int)connCounter > avgConnNumber)
    {
        statistics.update(Statistics::Actions::ChangeType, InvalidUsersParams::None, InvalidUsersParams::Malicious);
        throw UsersExceptionTypes::IsValid;
    }
}

void ControllerDDoSProtection::Users::ValidUsersParams::increaseConnCounter()
{
    time_t now = time(NULL);
    size_t numberOfIntervals = (now - updateConnCounterTime) / UPDATE_VALID_AVG_CONN_TIMER_INTERVAL;
    if (numberOfIntervals > 0)
    {
        if (avgConnNumber != NON_AVG_CONN_NUMBER)
        {
            for (size_t i = 0; i < numberOfIntervals - 1; ++i)
            {
                avgConnNumber = avgConnNumber / 2. + .5; // rounding
            }
            avgConnNumber = (avgConnNumber + connCounter) / 2. + .5;
        }
        else
        {
            avgConnNumber = connCounter;
        }
        connCounter = 1;
        updateConnCounterTime = updateConnCounterTime +
                numberOfIntervals * UPDATE_VALID_AVG_CONN_TIMER_INTERVAL;
        return;
    }
    ++connCounter;
    checkType();
}


// ControllerDDoSProtection::Users::InvalidUsersParams
void ControllerDDoSProtection::Users::InvalidUsersParams::checkType()
{
    // DDoS -> Malicious
    if (type == DDoS && connCounter >= INVALID_DDOS_AVG_CONN_NUMBER)
    {
        type = Malicious;
        statistics.update(Statistics::Actions::ChangeType, DDoS, Malicious);
    }
    // Malicious -> Valid
    if (params.isInvalidConnNumber(connCounter))
    {
        statistics.update(Statistics::Actions::ChangeType, Malicious, None);
        throw UsersExceptionTypes::IsValid;
    }
}

void ControllerDDoSProtection::Users::InvalidUsersParams::increaseConnCounter()
{
    time_t now = time(NULL);
    if (isObsolete())
    {
        statistics.update(Statistics::Actions::Reset, type, DDoS);
        reset();
        return;
    }
    if (now - updateConnCounterTime >= UPDATE_VALID_AVG_CONN_TIMER_INTERVAL)
    {
        connCounter = 1;
        updateTime = now;
        updateConnCounterTime = updateConnCounterTime +
                (now - updateConnCounterTime) / UPDATE_VALID_AVG_CONN_TIMER_INTERVAL * UPDATE_VALID_AVG_CONN_TIMER_INTERVAL;
        statistics.update(Statistics::Actions::Update, type, type);
        return;
    }
    ++connCounter;
    statistics.update(Statistics::Actions::Update, type, type);
    checkType();
}


// ControllerDDoSProtection::Users::Statistics
void ControllerDDoSProtection::Users::Statistics::update(Actions action,
                                                         InvalidUsersParams::InvalidUsersTypes typeBefore,
                                                         InvalidUsersParams::InvalidUsersTypes typeAfter)
{
    switch (typeBefore)
    {
    case InvalidUsersParams::InvalidUsersTypes::DDoS:
        if (action == ChangeType)
        {
            // DDoS --> Malicious
            ++invalidMaliciousUsersParams.number;
        }
        invalidDDoSUsersParams.updateNumbers(action);
        break;
    case InvalidUsersParams::InvalidUsersTypes::Malicious:
        if (action == Reset)
        {
            // Malicious --> DDoS
           ++invalidDDoSUsersParams.number;
        }
//        else if (action == ChangeType) { Malicious --> None }
        invalidMaliciousUsersParams.updateNumbers(action);
        break;
    default:
        LOG(ERROR) << "Invalid InvalidUsersParams::InvalidUsersTypes!";
        break;
    }
}

bool ControllerDDoSProtection::Users::Statistics::handle()
{
    size_t weight = 0;
    /* Invalid Malicious Users Params */
    if (invalidMaliciousUsersParams.checkedNumber >= INVALID_MALICIOUS_USERS_CHECKED_NUMBER)
    {
        weight += INVALID_MALICIOUS_USERS_CHECKED_NUMBER_WEIGHT;
    }
    UsersParams::NumberOfActions invalidMaliciousUsersNumberOfChanges = invalidMaliciousUsersParams.getNumberOfChanges();
    if (invalidMaliciousUsersNumberOfChanges.changeType >= INVALID_MALICIOUS_USERS_NUMBER_OF_CHANGE_TYPE)
    {
        weight += INVALID_MALICIOUS_USERS_NUMBER_OF_CHANGE_TYPE_WEIGHT;
    }

    /* Invalid DDoS Users Params */
    size_t invalidDDoSUsersNumber = invalidDDoSUsersParams.number;
    UsersParams::NumberOfActions invalidDDoSUsersNumberOfChanges = invalidDDoSUsersParams.getNumberOfChanges();
    size_t invalidDDoSUsersNumberOfInsert = invalidDDoSUsersNumberOfChanges.insert;
    if (!isStable &&
            invalidDDoSUsersNumberOfInsert / (float) invalidDDoSUsersNumber < IS_STABLE_CRITERIA)
    {
        isStable = true;
    }
    if (isStable && invalidDDoSUsersParams.number > INVALID_DDOS_USERS_NUMBER)
    {
        weight += INVALID_DDOS_USERS_NUMBER_WEIGHT;
    }
    if (isStable && invalidDDoSUsersNumberOfInsert > INVALID_DDOS_USERS_NUMBER_OF_INSERT)
    {
        weight += INVALID_DDOS_USERS_NUMBER_OF_INSERT_WEIGHT;
    }
    if (isStable &&
            invalidDDoSUsersNumberOfChanges.changeType / (float) invalidDDoSUsersNumber < INVALID_DDOS_USERS_NUMBER_OF_CHANGE_TYPE_NUMBER)
    {
        weight += INVALID_DDOS_USERS_NUMBER_OF_CHANGE_TYPE_NUMBER_WEIGHT;
    }

    if (weight >= IS_DDOS_WEIGHT)
    {
        return true;
    }
    return false;
}


// ControllerDDoSProtection::Users::Statistics::UsersParams
void ControllerDDoSProtection::Users::Statistics::UsersParams::updateNumbers(Actions action)
{
    switch (action)
    {
    case Reset:
        --number;
        ++numberOfChanges.reset;
        break;
    case ChangeType:
        --number;
        ++numberOfChanges.changeType;
        break;
    case Insert:
        ++number;
        ++numberOfChanges.insert;
        break;
    case Update:
        ++numberOfChanges.update;
        break;
    case Remove:
        --number;
        ++numberOfChanges.remove;
        break;
    default:
        LOG(ERROR) << "Invalid Statistics::Actions!";
        break;
    }
}


// ControllerDDoSProtection::Params
void ControllerDDoSProtection::Params::init()
{
    validAvgConnNumber.min = VALID_AVG_CONN_NUMBER_MIN;
    validAvgConnNumber.max = VALID_AVG_CONN_NUMBER_MAX;
    validAvgConnNumber.cur = (VALID_AVG_CONN_NUMBER_MIN + VALID_AVG_CONN_NUMBER_MAX) / 2;

    validPacketNumber.min = VALID_PACKET_NUMBER_MIN;
    validPacketNumber.max = VALID_PACKET_NUMBER_MAX;
    validPacketNumber.cur = (VALID_PACKET_NUMBER_MIN + VALID_PACKET_NUMBER_MAX) / 2;
}

void ControllerDDoSProtection::Params::updateValidAvgConnNumber()
{
    size_t avgConnNumber = 0;
    for (auto it = users.validUsers.begin(), end = users.validUsers.end(); it != end; ++it)
    {
        avgConnNumber += it->second.avgConnNumber;
    }
    avgConnNumber = avgConnNumber / (float) users.validUsers.size() + .5;

    validAvgConnNumber.cur = validateValidAvgConnNumber(avgConnNumber);
}

size_t ControllerDDoSProtection::Params::validateValidAvgConnNumber(size_t validAvgConnNumber_)
{
    LOG(INFO) << "ControllerDDoSProtectionParams::validateValidAvgConnNumber()";
    if (validAvgConnNumber_ > validAvgConnNumber.min && validAvgConnNumber_ < validAvgConnNumber.max)
    {
        return validAvgConnNumber_;
    }
    LOG(WARNING) << "Update of Valid Average Connection Number is failed: validAvgConnNumber = " << validAvgConnNumber_;
    return validAvgConnNumber.cur;
}


// ControllerDDoSProtection::FlowHandler
void ControllerDDoSProtection::FlowHandler::setNormalTimeouts (Flow *flow)
{
    LOG(INFO) << "ControllerDDoSProtection::FlowHandler::setNormalTimeouts()";
    flow->idleTimeout(NORMAL_IDLE_TIMEOUT);
    flow->timeToLive(NORMAL_HARD_TIMEOUT);
}

void ControllerDDoSProtection::FlowHandler::setShortTimeouts(Flow *flow)
{
    LOG(INFO) << "ControllerDDoSProtection::FlowHandler::setShortTimeouts()";
    flow->idleTimeout(SHORT_IDLE_TIMEOUT);
    flow->timeToLive(SHORT_HARD_TIMEOUT);
}
