#include "ControllerDDoSProtection.hh"
#include "AppObject.hh"

REGISTER_APPLICATION(ControllerDDoSProtection, {"controller", "switch-manager", ""})

bool ControllerDDoSProtection::isDDoS = false;
ControllerDDoSProtection::Users ControllerDDoSProtection::users;
ControllerDDoSProtection::Params ControllerDDoSProtection::params;
ControllerDDoSProtection::Users::Statistics ControllerDDoSProtection::Users::statistics;


// ControllerDDoSProtection
void ControllerDDoSProtection::init(Loader *loader, const Config& config)
{
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
    detectDDoSTimer->start(DETECT_DDOS_TIMER_INTERVAL * 1000);
}

void ControllerDDoSProtection::detectDDoSTimeout()
{
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
    /* TODO */
}

void ControllerDDoSProtection::clearInvalidUsersTimeout()
{
    /* TODO */
}

void ControllerDDoSProtection::getUsersStatistics (IPAddressV4 ipAddr, Switch* sw)
{
    /* TODO switch */
//    auto switches = m_switch_manager->switches();
//    for (auto sw : switches)
//    {
        of13::MultipartRequestFlow req;
        req.out_port(of13::OFPP_ANY);
        req.out_group(of13::OFPG_ANY);
        of13::Match match;
        /* TODO match */
        req.match(match);
        pdescr->request(sw->ofconn(), &req);
//    }
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

    for (auto& i : s)
    {
        uint64_t packetNumber = i.packet_count();
        minPacketNumber = std::min(packetNumber, minPacketNumber);
        if (params.isInvalidPacketNumber(packetNumber))
        {
            ++invalidFlowsNumber;
        }
    }
    /* TODO */
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
            emit app->UsersTypeChanged(srcIPAddrV4);
            return Stop;
        }
        if (validUser->second.typeIsChecked()) {
            FlowHandler::setNormalTimeouts(flow);
        }
        else
        {
            FlowHandler::setShortTimeouts(flow);
        }
        break;
    case Users::UsersTypes::Invalid:
        try
        {
            invalidUser->second.increaseConnCounter();
        }
        catch (Users::UsersExceptionTypes e)
        {
            emit app->UsersTypeChanged(srcIPAddrV4);
        }
//        Users::InvalidUsersParams::InvalidUsersTypes invalidType = invalidUser->second.getType();
//        bool invalidTypeIsChecked = invalidUser->second.typeIsChecked();
        if (isDDoS)
        {
            FlowHandler::setShortTimeouts(flow);
        }
        /* TODO logic */
//        else if (invalidType == Users::InvalidUsersParams::InvalidUsersTypes::Malicious)
//        { }
        else {
            FlowHandler::setNormalTimeouts(flow);
        }
        break;
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
    InvalidUsersParams invalidUsersParams;
    invalidUsers.insert (std::pair <IPAddressV4, InvalidUsersParams> (ipAddr, invalidUsersParams));
    statistics.update(Statistics::Actions::Insert,
                      InvalidUsersParams::InvalidUsersTypes::None,
                      InvalidUsersParams::InvalidUsersTypes::DDoS);
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
    /* TODO */
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
    /* TODO */
    return true;
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


// ControllerDDoSProtection::FlowHandler
void ControllerDDoSProtection::FlowHandler::setNormalTimeouts (Flow *flow)
{
    flow->idleTimeout(NORMAL_IDLE_TIMEOUT);
    flow->timeToLive(NORMAL_HARD_TIMEOUT);
}

void ControllerDDoSProtection::FlowHandler::setShortTimeouts(Flow *flow)
{
    flow->idleTimeout(SHORT_IDLE_TIMEOUT);
    flow->timeToLive(SHORT_HARD_TIMEOUT);
}
