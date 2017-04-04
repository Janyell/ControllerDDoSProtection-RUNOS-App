#pragma once

#include <mutex>
#include <math.h>

#include "Application.hh"
#include "Loader.hh"
#include "Switch.hh"
#include "HostManager.hh"

#include "ddos/Users.hh"
#include "ddos/Params.hh"

// EtherType
#define IPv4_TYPE 0x0800
#define IPv6_TYPE 0x86DD

class ControllerDDoSProtection : public Application {
SIMPLE_APPLICATION (ControllerDDoSProtection, "controller-ddos-protection")
Q_OBJECT

public:
    typedef uint32_t IPAddressV4;
    typedef uint64_t Dpid;
    typedef uint32_t InPort; /* uint8_t - packed size */

    void init (Loader* loader, const Config& config) override;
    void startUp (Loader* loader) override;

private:

    Decision processMiss (SwitchConnectionPtr conn, IPAddressV4 ipAddr, Decision decision);

    static bool isDDoS;

    QTimer* detectDDoSTimer;
    static const time_t DETECT_DDOS_TIMER_INTERVAL = 5;

    QTimer* updateValidAvgConnTimer; // Users::UPDATE_VALID_AVG_CONN_TIMER_INTERVAL

    QTimer* clearInvalidUsersTimer; // Users::CLEAR_INVALID_USERS_TIMER_INTERVAL

    static constexpr double INVALID_FLOW_PERCENT = 0.1;

    OFTransaction* oftran;
    HostManager* host_manager;

    static Users users;
    static Params params;


    // Detection using SPRT
    class SPRTdetection {
    public:
        struct Dn {
            size_t n;
            double din;
            size_t ip_count;
            Dn (size_t n_ = 0, double din_ = 1.0, size_t ip_count_ = 0) : n(n_), din(din_), ip_count(ip_count_) {}
        };
        typedef std::map<InPort, Dn> Imap;
        typedef std::map<Dpid, Imap> Dmap;

        enum InPortTypes {
            Uncompromised,
            Compromised,
            Unknown
        };

        SPRTdetection (): a(countA()), b(countB()) {}
        bool isDDoS();
        InPortTypes isCompromisedInPort (Dpid dpid, InPort in_port, uint64_t packet_count, size_t packet_count_max = C_MAX);

        struct SPRTconfig {
            const double alpha;
            const double beta;
            double lambda0;
            double lambda1;
            SPRTconfig (double alpha_ = ALPHA, double beta_ = BETA,
                        double lambda0_ = LAMBDA_0, double lambda1_ = LAMBDA_1) :
                alpha(alpha_), beta(beta_), lambda0(lambda0_), lambda1(lambda1_) {}
            static constexpr double ALPHA = 0.01;
            static constexpr double BETA = 0.02;
            static constexpr double LAMBDA_0 = 0.33;
            static constexpr double LAMBDA_1 = 0.6;
        };



    private:
        SPRTconfig config;
        const double a;
        const double b;

        Dmap d;

        void countDin(Imap::iterator& dn, size_t c, size_t cMax = C_MAX)
        {

            ++(dn->second.n);
            dn->second.din += (c <= cMax) ? log( config.lambda1 / config.lambda0 ) :
                                     log( (1 - config.lambda1) / (1 - config.lambda0) );
        }
        double countA() { return config.beta / (1 - config.alpha); }
        double countB() { return (1 - config.beta) / config.alpha; }
        InPortTypes checkDin (Imap::iterator& dn);

        bool getDi (Dpid dpid, InPort i, Imap::iterator& dn);
        bool searchDpid (Dpid dpid, Dmap::iterator& di);
        bool searchInPort (InPort i, Dmap::iterator di, Imap::iterator& dn);
        bool insertDpid (Dpid dpid, Dmap::iterator& di);
        bool insertInPort(InPort i, Dmap::iterator di, Imap::iterator& dn);

        static const size_t C_MAX = 3;

    } static detection;

signals:
    void UsersTypeChanged (SwitchConnectionPtr conn, IPAddressV4 ipAddr);
private slots:
    void detectDDoSTimeout();
    void updateValidAvgConnTimeout();
    void clearInvalidUsersTimeout();
    void getUsersStatistics (SwitchConnectionPtr conn, IPAddressV4 ipAddr);
    void usersStatisticsArrived (SwitchConnectionPtr conn, std::shared_ptr<OFMsgUnion> reply);
    void flowRemoved (SwitchConnectionPtr conn, of13::FlowRemoved fr);
};
