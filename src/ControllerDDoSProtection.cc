#include "ControllerDDoSProtection.hh"
#include "AppObject.hh"
#include "Controller.hh"
#include "SwitchConnection.hh"

#include "api/Packet.hh"
#include "api/PacketMissHandler.hh"
#include "api/TraceablePacket.hh"
#include "types/ethaddr.hh"
#include "oxm/openflow_basic.hh"

REGISTER_APPLICATION(ControllerDDoSProtection, {"controller", "switch-manager", ""})

bool ControllerDDoSProtection::isDDoS = false;
size_t ControllerDDoSProtection::detectNotDDoScounter = 0;
Users ControllerDDoSProtection::users;
Params ControllerDDoSProtection::params;
ControllerDDoSProtection::SPRTdetection ControllerDDoSProtection::detection;


class DecisionHandler {
public:
    static Decision setNormalTimeouts (Decision decision)
    {
        return decision.idle_timeout(std::chrono::seconds(NORMAL_IDLE_TIMEOUT))
                .hard_timeout(std::chrono::minutes(NORMAL_HARD_TIMEOUT));
    }

    static Decision setShortTimeouts (Decision decision)
    {
        return decision.idle_timeout(std::chrono::seconds(SHORT_IDLE_TIMEOUT))
                .hard_timeout(std::chrono::minutes(SHORT_HARD_TIMEOUT));
    }
    static Decision drop (Decision decision)
    {
        return decision.drop()
                .idle_timeout(std::chrono::seconds(std::chrono::seconds::zero()))
                .hard_timeout(std::chrono::seconds(60))
                .return_();
    }
private:
    static const uint16_t NORMAL_HARD_TIMEOUT;
    static const uint16_t NORMAL_IDLE_TIMEOUT;
    static const uint16_t SHORT_HARD_TIMEOUT;
    static const uint16_t SHORT_IDLE_TIMEOUT;
};

const uint16_t DecisionHandler::NORMAL_HARD_TIMEOUT = 30;   // minutes
const uint16_t DecisionHandler::NORMAL_IDLE_TIMEOUT = 60;   // seconds
const uint16_t DecisionHandler::SHORT_HARD_TIMEOUT = 5;     // minutes
const uint16_t DecisionHandler::SHORT_IDLE_TIMEOUT = 10;    // seconds

void ControllerDDoSProtection::init(Loader *loader, const Config& config)
{
    LOG(INFO) << "ControllerDDoSProtection::init()";

    qRegisterMetaType<IPAddressV4>("IPAddressV4");

    detectDDoSTimer = new QTimer(this);
    updateValidAvgConnTimer = new QTimer(this);
    clearInvalidUsersTimer = new QTimer(this);

    Controller* ctrl = Controller::get(loader);
    host_manager = HostManager::get(loader);
    ctrl->registerHandler("ddos-protection",
        [=](SwitchConnectionPtr conn)
        {
        const auto ofb_eth_type = oxm::eth_type();
        const auto ofb_ipv4_src = oxm::ipv4_src();
        const auto ofb_ipv4_dst = oxm::ipv4_dst();

            return [=](Packet& pkt, FlowPtr, Decision decision) mutable
            {
                auto tpkt = packet_cast<TraceablePacket>(pkt);
                if (pkt.test(ofb_eth_type == IPv4_TYPE)) {
                    IPv4Addr srcIPAddr = tpkt.watch(ofb_ipv4_src);
                    IPAddressV4 srcIPAddrV4 = srcIPAddr.to_number();

                    IPv4Addr dstIPAddr = tpkt.watch(ofb_ipv4_dst);
                    IPAddressV4 dstIPAddrV4 = dstIPAddr.to_number();

                    if (srcIPAddrV4 == IPAddress("0.0.0.0").getIPv4() || dstIPAddrV4 == IPAddress("0.0.0.0").getIPv4())
                    {
                        return decision;
                    }

//                    LOG(INFO) << "processMiss";
                    LOG(INFO) << AppObject::uint32_t_ip_to_string(srcIPAddrV4) << "\t-->\t" <<AppObject::uint32_t_ip_to_string(dstIPAddrV4);

                    return processMiss(conn, srcIPAddrV4, decision);
                }
                return decision;
            };
        }
    );
    params.init();

    QObject::connect(detectDDoSTimer, SIGNAL(timeout()), this, SLOT(detectDDoSTimeout()));
    QObject::connect(updateValidAvgConnTimer, SIGNAL(timeout()), this, SLOT(updateValidAvgConnTimeout()));
    QObject::connect(clearInvalidUsersTimer, SIGNAL(timeout()), this, SLOT(clearInvalidUsersTimeout()));
    QObject::connect(this, SIGNAL(UsersTypeChanged(SwitchConnectionPtr, IPAddressV4)), this,
                     SLOT(getUsersStatistics(SwitchConnectionPtr, IPAddressV4)));

    // Регистрация приложения для статического обмена пакетами с коммутаторами.
    oftran = ctrl->registerStaticTransaction(this);

    QObject::connect(oftran, &OFTransaction::response,
                     this, &ControllerDDoSProtection::usersStatisticsArrived);

    QObject::connect(oftran, &OFTransaction::error,
    [](SwitchConnectionPtr conn, std::shared_ptr<OFMsgUnion> msg)
    {
        of13::Error& error = msg->error;
        LOG(ERROR) << "Switch reports error for OFPT_MULTIPART_REQUEST: "
            << "type " << (int) error.type() << " code " << error.code();
        // Send request again
        // Switch.cc 91 FIXME: use switch-generate ofmsg and limit retry count
        // conn->send(error.data(), error.data_len());
    });

    // Коммутатор сообщил об удалении потока.
    QObject::connect(ctrl, &Controller::flowRemoved, this, &ControllerDDoSProtection::flowRemoved);
}


void ControllerDDoSProtection::startUp (Loader *loader)
{
    detectDDoSTimer->start (DETECT_DDOS_TIMER_INTERVAL * 1000);
    updateValidAvgConnTimer->start (Users::UPDATE_VALID_AVG_CONN_TIMER_INTERVAL * 1000);
    clearInvalidUsersTimer->start (Users::CLEAR_INVALID_USERS_TIMER_INTERVAL * 1000);
}


void ControllerDDoSProtection::detectDDoSTimeout()
{
//    LOG(INFO) << "ControllerDDoSProtection::detectDDoSTimeout()";
    users.update();
    Users::Statistics statistics = users.getStatistics();
    bool isDetectedDDoS = statistics.handle();
    setDDoS(isDetectedDDoS);
    users.resetStatistics();
}


void ControllerDDoSProtection::updateValidAvgConnTimeout()
{
    LOG(INFO) << "ControllerDDoSProtection::updateValidAvgConnTimeout()";
    params.updateValidAvgConnNumber(users);
}


void ControllerDDoSProtection::clearInvalidUsersTimeout()
{
//    LOG(INFO) << "ControllerDDoSProtection::clearInvalidUsersTimeout()";
    /* todo */
}


void ControllerDDoSProtection::getUsersStatistics (SwitchConnectionPtr conn, IPAddressV4 ipAddr)
{
    LOG(INFO) << "ControllerDDoSProtection::getUsersStatistics (" << AppObject::uint32_t_ip_to_string(ipAddr) << ")";
    of13::MultipartRequestFlow mprf;
    mprf.table_id(of13::OFPTT_ALL);
    mprf.out_port(of13::OFPP_ANY);
    mprf.out_group(of13::OFPG_ANY);
//    of13::IPv4Src* oxm = new of13::IPv4Src(ipAddr);
    Host* host = host_manager->getHost(ipAddr);
    if (host == nullptr)
    {
        LOG(WARNING) << "Cannot get host by IP: " << AppObject::uint32_t_ip_to_string(ipAddr) << " from HostManager";
        return;
    }
    of13::EthSrc* oxm = new of13::EthSrc(host->mac());
    mprf.add_oxm_field(oxm);
//    mprf.cookie(0x0);  // match: cookie & mask == field.cookie & mask
//    mprf.cookie_mask(0x0);
//    mprf.flags(0);
    oftran->request(conn, mprf);
}


void ControllerDDoSProtection::usersStatisticsArrived(SwitchConnectionPtr conn, std::shared_ptr<OFMsgUnion> reply)
{
    auto type = reply->base()->type();
    if (type != of13::OFPT_MULTIPART_REPLY)
    {
        LOG(ERROR) << "Unexpected response of type " << type
                << " received, expected OFPT_MULTIPART_REPLY";
        return;
    }

    of13::MultipartReplyFlow stats = reply->multipartReplyFlow;
    std::vector<of13::FlowStats> s = stats.flow_stats();

    if (s.size() == 0) {
        LOG(INFO) << "No flow stats";
        return;
    }

//    of13::IPv4Src* addrPtr = s[0].match().ipv4_src();
    of13::EthSrc* addrPtr = s[0].match().eth_src();
    if (addrPtr == nullptr)
    {
        LOG(WARNING) << "Cannot get ETH_SRC from Multipart Reply Message";
        return;
    }

    EthAddress ethAddr = addrPtr->value();
    Host* host = host_manager->getHost(ethAddr.to_string());
    if (host == nullptr)
    {
        LOG(WARNING) << "Cannot get host by MAC: " << ethAddr.to_string() << " from HostManager";
        return;
    }

    IPAddress ipAddr = host->ip();
    IPAddressV4 ipAddrV4 = ipAddr.getIPv4();

    LOG(INFO) << "ControllerDDoSProtection::usersStatisticsArrived (" << AppObject::uint32_t_ip_to_string(ipAddrV4) << ")";

    std::map<IPAddressV4, Users::ValidUsersParams>::iterator validUser;
    std::map<IPAddressV4, Users::InvalidUsersParams>::iterator invalidUser;
    Users::UsersTypes userType = users.get(ipAddrV4, validUser, invalidUser);

    for (auto& i : s)
    {
        uint64_t packetNumber = i.packet_count();
        of13::EthType* eth_type_ptr = i.match().eth_type();
        if (eth_type_ptr == nullptr)
        {
            LOG(WARNING) << "Cannot get ETH_TYPE from Flow Stats Message";
            continue;
        }

        if (packetNumber != 0 && eth_type_ptr->value() == IPv4_TYPE) {
            switch (userType)
            {
            case Users::UsersTypes::Invalid:
                invalidUser->second.updatePacketNumber(params, packetNumber);
                break;
            case Users::UsersTypes::Valid:
                validUser->second.updatePacketNumber(params, packetNumber);
                break;
            case Users::UsersTypes::Unknown:
                throw Users::UsersExceptionTypes::IsUnknown;
            }
        } // else useless stats
    }

    switch (userType)
    {
    case Users::UsersTypes::Invalid:
        try
        {
            invalidUser->second.updateIsChecked(params);
        }
        catch (Users::UsersExceptionTypes)
        {
            users.validate(invalidUser);
        }
        break;
    case Users::UsersTypes::Valid:
        try
        {
            validUser->second.updateIsChecked(params);
        }
        catch (Users::UsersExceptionTypes)
        {
            users.invalidate(validUser);
        }
        break;
    case Users::UsersTypes::Unknown:
        throw Users::UsersExceptionTypes::IsUnknown;
    }
    detectDDoSTimeout();
}

Decision ControllerDDoSProtection::processMiss (SwitchConnectionPtr conn, IPAddressV4 ipAddr, Decision decision)
{
//    params.print();

    std::map<IPAddressV4, Users::ValidUsersParams>::iterator validUser;
    std::map<IPAddressV4, Users::InvalidUsersParams>::iterator invalidUser;
    Users::UsersTypes type = users.get(ipAddr, validUser, invalidUser);

//    LOG(INFO) << "ControllerDDoSProtection::processMiss (" << AppObject::uint32_t_ip_to_string(ipAddr) << ")";

    switch (type)
    {
    case Users::UsersTypes::Valid:
    {
        LOG(INFO) << "Users::UsersTypes::Valid";
        Users::ValidUsersParams& userParams = validUser->second;
        try
        {
            userParams.increaseConnCounter(params);
        }
        catch (Users::UsersExceptionTypes)
        {
            LOG(INFO) << "Valid --> Valid or Malicious";
            emit UsersTypeChanged(conn, ipAddr);
        }
        decision = DecisionHandler::setNormalTimeouts(decision);
        break;
    }
    case Users::UsersTypes::Invalid:
    {
        LOG(INFO) << "Users::UsersTypes::Invalid";        
        Users::InvalidUsersParams& userParams = invalidUser->second;
        try
        {
            userParams.increaseConnCounter(params);
        }
        catch (Users::UsersExceptionTypes)
        {
            LOG(INFO) << "Malicious --> Valid or Malicious";
            emit UsersTypeChanged(conn, ipAddr);
        }

//        invalidUser->second.print();

        Users::InvalidUsersParams::InvalidUsersTypes invalidType = userParams.getType();
        bool invalidTypeIsChecked = userParams.typeIsChecked();
        if (invalidType == Users::InvalidUsersParams::InvalidUsersTypes::Malicious
                && invalidTypeIsChecked == 1) //
        {
            // Block
            return DecisionHandler::drop(decision);
        }

        decision = isDDoS ? DecisionHandler::setShortTimeouts(decision) : DecisionHandler::setNormalTimeouts(decision);
        break;
    }
    case Users::UsersTypes::Unknown:
        LOG(INFO) << "Users::UsersTypes::Unknown";
        users.insert(ipAddr);
        decision = isDDoS ? DecisionHandler::setShortTimeouts(decision) : DecisionHandler::setNormalTimeouts(decision);
        break;
    }
    return decision;
}


void ControllerDDoSProtection::flowRemoved (SwitchConnectionPtr conn, of13::FlowRemoved fr) {
//    LOG(INFO) << "ControllerDDoSProtection::flowRemoved()";
    Dpid dpid = conn->dpid();
//    LOG(INFO) << "dpid = " << dpid;

    uint64_t packet_count = fr.packet_count();
    if (packet_count == 0)
        return; // useless
//    LOG(INFO) << "packet_count = " << packet_count;

    of13::InPort* in_port_ptr = fr.match().in_port();
    InPort in_port;
    if (in_port_ptr == nullptr)
    {
        LOG(WARNING) << "Cannot get IN_PORT from Flow Removed Message";
        of13::EthSrc* eth_addr_ptr = fr.match().eth_src();
        if (eth_addr_ptr == nullptr)
        {
            LOG(WARNING) << "Cannot get ETH_SRC from Flow Removed Message";
            return;
        }

        EthAddress eth_addr = eth_addr_ptr->value();
        Host* host = host_manager->getHost(eth_addr.to_string());
        if (host == nullptr)
        {
            LOG(WARNING) << "Cannot get host by MAC: " << eth_addr.to_string() << " from HostManager";
            return;
        }

        in_port = host->switchPort();
    } else {
        in_port = in_port_ptr->value();
    }
//    LOG(INFO) << "in_port = " << in_port;

    SPRTdetection::InPortTypes in_port_type = detection.isCompromisedInPort(dpid, in_port, packet_count, params.getValidPacketNumber().cur);
    if (in_port_type == SPRTdetection::InPortTypes::Compromised)
    {
        LOG(INFO) << "Switch ID: " << dpid << ", in_port: " << in_port << " is compromised!";
        setDDoS (detection.isDDoS());
    }

    // Users check
    of13::EthType* eth_type_ptr = fr.match().eth_type();
    if (eth_type_ptr == nullptr || eth_type_ptr->value() != IPv4_TYPE)
        return; // useless

    of13::EthSrc* addrPtr = fr.match().eth_src();
    if (addrPtr == nullptr)
    {
        LOG(WARNING) << "Cannot get ETH_SRC from Flow Removed Message";
        return;
    }

    EthAddress ethAddr = addrPtr->value();
    Host* host = host_manager->getHost(ethAddr.to_string());
    if (host == nullptr)
    {
        LOG(WARNING) << "Cannot get host by MAC: " << ethAddr.to_string() << " from HostManager";
        return;
    }

    IPAddress ipAddr = host->ip();
    IPAddressV4 ipAddrV4 = ipAddr.getIPv4();

    std::map<IPAddressV4, Users::ValidUsersParams>::iterator validUser;
    std::map<IPAddressV4, Users::InvalidUsersParams>::iterator invalidUser;
    Users::UsersTypes userType = users.get(ipAddrV4, validUser, invalidUser);
    LOG(INFO) << "IP: " << AppObject::uint32_t_ip_to_string(ipAddrV4) << ", packet_count: " << packet_count;
    switch (userType)
    {
    case Users::UsersTypes::Invalid:
        try
        {
            Users::InvalidUsersParams& userParams = invalidUser->second;
            userParams.updatePacketNumber(params, packet_count);
            userParams.updateIsChecked(params);
        }
        catch (Users::UsersExceptionTypes)
        {
            users.validate(invalidUser);
        }
        break;
    case Users::UsersTypes::Valid:
        try
        {
            Users::ValidUsersParams& userParams = validUser->second;
            userParams.updatePacketNumber(params, packet_count);
            userParams.updateIsChecked(params);
        }
        catch (Users::UsersExceptionTypes)
        {
            users.invalidate(validUser);
        }

        break;
    case Users::UsersTypes::Unknown:
        throw Users::UsersExceptionTypes::IsUnknown;
    }
}


// ControllerDDoSProtection::SPRTdetection
bool ControllerDDoSProtection::SPRTdetection::isDDoS() {
    return true;
}


ControllerDDoSProtection::SPRTdetection::InPortTypes
ControllerDDoSProtection::SPRTdetection::isCompromisedInPort (Dpid dpid, InPort in_port, uint64_t packet_count, size_t packet_count_max)
{
    Imap::iterator dn;
    getDi(dpid, in_port, dn);
    countDin(dn, packet_count, packet_count_max);
    return checkDin(dn);
}


ControllerDDoSProtection::SPRTdetection::InPortTypes
ControllerDDoSProtection::SPRTdetection::checkDin (Imap::iterator& dn)
{
    double din = dn->second.din;
    if (din <= b)
        return InPortTypes::Uncompromised;
    if (din >= a)
        return InPortTypes::Compromised;
    // else
    return InPortTypes::Unknown;
}


bool ControllerDDoSProtection::SPRTdetection::getDi (Dpid dpid, InPort i, Imap::iterator& dn)
{
    Dmap::iterator di;
    if (searchDpid(dpid, di))
    {
        if (searchInPort(i, di, dn))
            return true;
        // or insert one level (InPort)
        insertInPort(i, di, dn);
        return false;
    }
    // or insert two levels (Dpid & InPort)
    insertDpid(dpid, di);
    insertInPort(i, di, dn);
    return false;
}


bool ControllerDDoSProtection::SPRTdetection::searchDpid (Dpid dpid, Dmap::iterator& di)
{
    Dmap::iterator it = d.find(dpid);
    if (it != d.end())
    {
        di = it;
        return true;
    }
    return false;
}


bool ControllerDDoSProtection::SPRTdetection::searchInPort (InPort i, Dmap::iterator di, Imap::iterator& dn)
{
    Imap::iterator it = di->second.find(i);
    if (it != di->second.end())
    {
        dn = it;
        return true;
    }
    return false;
}


bool ControllerDDoSProtection::SPRTdetection::insertDpid (Dpid dpid, Dmap::iterator& di)
{
    Imap imap;
    std::pair<Dmap::iterator, bool> ret = d.insert(std::pair<Dpid, Imap>(dpid, imap));
    di = ret.first;
    return ret.second;
}


bool ControllerDDoSProtection::SPRTdetection::insertInPort(InPort i, Dmap::iterator di, Imap::iterator& dn)
{
    Dn d0;
    std::pair<Imap::iterator, bool> ret = di->second.insert(std::pair<InPort, Dn>(i, d0));
    dn = ret.first;
    return ret.second;
}

void ControllerDDoSProtection::setDDoS (bool value)
{
    if (!isDDoS && value)
    {
        isDDoS = true;
        detectNotDDoScounter = 0;
        LOG(INFO) << "DDoS is detected";
        return;
    }
    if (isDDoS && !value && ++detectNotDDoScounter >= DETECT_NOT_DDOS_NUMBER)
    {
        isDDoS = false;
        LOG(INFO) << "No DDoS is detected";
    }
}
