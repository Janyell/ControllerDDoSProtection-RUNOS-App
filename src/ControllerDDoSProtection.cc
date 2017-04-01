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
private:
    static const uint16_t NORMAL_HARD_TIMEOUT;
    static const uint16_t NORMAL_IDLE_TIMEOUT;
    static const uint16_t SHORT_HARD_TIMEOUT;
    static const uint16_t SHORT_IDLE_TIMEOUT;
};

const uint16_t DecisionHandler::NORMAL_HARD_TIMEOUT = 300; // 30
const uint16_t DecisionHandler::NORMAL_IDLE_TIMEOUT = 60; // 60
const uint16_t DecisionHandler::SHORT_HARD_TIMEOUT = 60;
const uint16_t DecisionHandler::SHORT_IDLE_TIMEOUT = 10;


void ControllerDDoSProtection::init(Loader *loader, const Config& config)
{
    LOG(INFO) << "ControllerDDoSProtection::init()";
    detectDDoSTimer = new QTimer(this);
    updateValidAvgConnTimer = new QTimer(this);
    clearInvalidUsersTimer = new QTimer(this);
    Controller* ctrl = Controller::get(loader);
    ctrl->registerHandler("ddos-protection",
        [=](SwitchConnectionPtr conn)
        {
        const auto ofb_eth_type = oxm::eth_type();
        const auto ofb_ipv4_src = oxm::ipv4_src();
        const auto ofb_ipv4_dst = oxm::ipv4_dst();

            return [=](Packet& pkt, FlowPtr, Decision decision) mutable
            {
                if (pkt.test(ofb_eth_type == IPv4_TYPE)) {
                    IPv4Addr srcIPAddr = pkt.load(ofb_ipv4_src);
                    IPAddressV4 srcIPAddrV4 = srcIPAddr.to_number();

                    IPv4Addr dstIPAddr = pkt.load(ofb_ipv4_dst);
                    IPAddressV4 dstIPAddrV4 = dstIPAddr.to_number();

                    if (srcIPAddrV4 == IPAddress("0.0.0.0").getIPv4() || dstIPAddrV4 == IPAddress("0.0.0.0").getIPv4())
                    {
                        return decision;
                    }

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
    if (isDetectedDDoS) {
        isDDoS = true;
    }
    users.resetStatistics();
}


void ControllerDDoSProtection::updateValidAvgConnTimeout()
{
    LOG(INFO) << "ControllerDDoSProtection::updateValidAvgConnTimeout()";
    params.updateValidAvgConnNumber(users);
}


void ControllerDDoSProtection::clearInvalidUsersTimeout()
{
    LOG(INFO) << "ControllerDDoSProtection::clearInvalidUsersTimeout()";
    /* todo */
}


void ControllerDDoSProtection::getUsersStatistics (SwitchConnectionPtr conn, IPAddressV4 ipAddr)
{
    LOG(INFO) << "ControllerDDoSProtection::getUsersStatistics(" << AppObject::uint32_t_ip_to_string(ipAddr) << ")";
    of13::MultipartRequestFlow mprf;
    mprf.table_id(of13::OFPTT_ALL);
    mprf.out_port(of13::OFPP_ANY);
    mprf.out_group(of13::OFPG_ANY);
    mprf.add_oxm_field(new of13::IPv4Src(IPAddress(ipAddr)));
    mprf.cookie(0x0);
    mprf.cookie_mask(0x0);
    mprf.flags(0);
    oftran->request(conn, mprf);
}


void ControllerDDoSProtection::usersStatisticsArrived(SwitchConnectionPtr conn, std::shared_ptr<OFMsgUnion> reply)
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

//    of13::Match match = s[0].match();
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


Decision ControllerDDoSProtection::processMiss (SwitchConnectionPtr conn, IPAddressV4 ipAddr, Decision decision)
{
    std::map<IPAddressV4, Users::ValidUsersParams>::iterator validUser;
    std::map<IPAddressV4, Users::InvalidUsersParams>::iterator invalidUser;
    Users::UsersTypes type = users.get(ipAddr, validUser, invalidUser);

    switch (type)
    {
    case Users::UsersTypes::Valid:
        try
        {
            (validUser->second).increaseConnCounter(params);
        }
        catch (Users::UsersExceptionTypes)
        {
            // Valid -> Valid or Malicious
            emit UsersTypeChanged(conn, ipAddr);
        }
        decision = (validUser->second).typeIsChecked() ? DecisionHandler::setNormalTimeouts(decision) :
                                                         DecisionHandler::setShortTimeouts(decision);
        break;
    case Users::UsersTypes::Invalid:
    {
        try
        {
            invalidUser->second.increaseConnCounter(params);
        }
        catch (Users::UsersExceptionTypes)
        {
            // Malicious -> Valid or Malicious
            emit UsersTypeChanged(conn, ipAddr);
        }
        Users::InvalidUsersParams::InvalidUsersTypes invalidType = (invalidUser->second).getType();
        bool invalidTypeIsChecked = (invalidUser->second).typeIsChecked();
        if (invalidType == Users::InvalidUsersParams::InvalidUsersTypes::Malicious
                && invalidTypeIsChecked == 1)
        {
            // Block
            decision = DecisionHandler::setNormalTimeouts(decision);
            return decision.drop().return_();
        }

        /* ? */
        decision = isDDoS ? DecisionHandler::setShortTimeouts(decision) : DecisionHandler::setNormalTimeouts(decision);
        break;
    }
    case Users::UsersTypes::Unknown:
        users.insert(ipAddr);
        decision = isDDoS ? DecisionHandler::setShortTimeouts(decision) : DecisionHandler::setNormalTimeouts(decision);
        break;
    }
    return decision;
}


void ControllerDDoSProtection::flowRemoved (SwitchConnectionPtr conn, of13::FlowRemoved fr) {
    LOG(INFO) << "ControllerDDoSProtection::flowRemoved()";
    Dpid dpid = conn->dpid();
    LOG(INFO) << "dpid = " << dpid;
    of13::InPort* in_port_ptr = fr.match().in_port();
    if (in_port_ptr == NULL)
    {
        LOG(WARNING) << "Cannot get IN_PORT from Flow Removed Message";
        return;
    }
    InPort in_port = in_port_ptr ->value();
    LOG(INFO) << "in_port = " << in_port;
    uint64_t packet_count = fr.packet_count();
    LOG(INFO) << "packet_count = " << packet_count;
    SPRTdetection::InPortTypes in_port_type = detection.isCompromisedInPort(dpid, in_port, packet_count, params.getValidPacketNumber().cur);
    if (in_port_type == SPRTdetection::InPortTypes::Compromised)
    {
        isDDoS = detection.isDDoS();
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
