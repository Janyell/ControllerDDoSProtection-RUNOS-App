#pragma once

#include "Application.hh"
#include "OFMessageHandler.hh"
#include "ILinkDiscovery.hh"

// EtherType
#define IPv4_TYPE 0x0800
#define IPv_TYPE 0x86DD

typedef uint32_t IPAddressV4;

class ControllerDDoSProtection : public Application, OFMessageHandlerFactory {
SIMPLE_APPLICATION (ControllerDDoSProtection, "controller-ddos-protection")
Q_OBJECT
public:
    void init (Loader* loader, const Config& config) override;
    void startUp (Loader* provider) override;
    std::string orderingName() const override { return "controller-ddos-protection"; }
    std::unique_ptr<OFMessageHandler> makeOFMessageHandler() override
    {
        return std::unique_ptr<OFMessageHandler> (new Handler(this));
    }
    bool isPrereq (const std::string &name) const override { return (name == "forwarding"); }

private:
    class Handler: public OFMessageHandler {
    public:
        Handler (ControllerDDoSProtection* app_) : app(app_) { }
        Action processMiss (OFConnection* ofconn, Flow* flow) override;
    private:
        ControllerDDoSProtection* app;
    };

    static bool isDDoS;

    QTimer* DetectDDoSTimer;
    static const size_t DETECT_DDOS_TIMER_INTERVAL = 5;

    QTimer* ClearInvalidUsersTimer; // TODO
    static const size_t CLEAR_INVALID__USERS_TIMER_INTERVAL = 500;

    static void getStatisticsFromSwitch() {}

    //    std::mutex db_lock; TODO

    class Users {
    public:
        enum UsersTypes {
            Valid,
            Invalid,
            Unknown
        };

        class ValidUsersParams {
        public:
            ValidUsersParams (size_t _connCounter = 1, int _avgConnNumber = NON_AVG_CONN_NUMBER):
                connCounter(_connCounter), avgConnNumber(_avgConnNumber), updateConnCounterTime(time(NULL)) { }
            void increaseConnCounter();
        private:
            size_t connCounter;
            int avgConnNumber;
            time_t updateConnCounterTime;

            static const int NON_AVG_CONN_NUMBER = -1;
        };

        class InvalidUsersParams {
        public:
            enum InvalidUsersTypes {
                DDoS,
                Malicious,
                None // Null or Valid
            };
            InvalidUsersParams (size_t _connCounter = 1,
                                time_t _hardTimeout = HARD_TIMEOUT,
                                time_t _idleTimeout = IDLE_TIMEOUT)
                : type(DDoS), connCounter(_connCounter), hardTimeout(_hardTimeout), idleTimeout(_idleTimeout)
            {
                createTime = updateTime = updateConnCounterTime = time(NULL);
            }
            void increaseConnCounter();
            bool isObsolete()
            {
                time_t now = time(NULL);
                if (now - updateTime >= idleTimeout || now - createTime >= hardTimeout)
                    return true;
                return false;
            }
            InvalidUsersTypes getType() { return type; }
        private:
            void checkType();
            bool isValid() { return false; }
            void reset (time_t _hardTimeout = HARD_TIMEOUT,
                        time_t _idleTimeout = IDLE_TIMEOUT)
            {
                connCounter = 1;
                hardTimeout = _hardTimeout;
                idleTimeout = _idleTimeout;
                createTime = updateTime = updateConnCounterTime = time(NULL);
                type = DDoS;
            }
            InvalidUsersTypes type;
            size_t connCounter;
            time_t hardTimeout;
            time_t idleTimeout;
            time_t createTime;
            time_t updateTime;
            time_t updateConnCounterTime;
            static const size_t INVALID_DDOS_AVG_CONN_NUMBER = 2;
            static const time_t HARD_TIMEOUT = 6000;
            static const time_t IDLE_TIMEOUT = 600;
        };

        class Statistics {
        public:
            enum Actions {
                Reset,
                Insert,
                ChangeType,
                Update,
                Remove
            };
            class UsersParams {
            public:
                UsersParams() : number(0), numberOfChanges() { }
                void reset()
                {
                    // number is not reset
                    numberOfChanges.clear();
                }
                void updateNumbers(Actions action);
                size_t number;
            private:
                struct NumberOfActions {
                    size_t reset;
                    size_t insert;
                    size_t changeType;
                    size_t update;
                    size_t remove;
                    NumberOfActions(): reset(0), insert(0), changeType(0), update(0), remove(0) { }
                    void clear() {
                        reset = insert = changeType = update = remove = 0;
                    }
                } numberOfChanges;
            };
            void reset() {
                invalidDDoSUsersParams.reset();
                invalidMaliciousUsersParams.reset();
            }
            void update (Actions action,
                         InvalidUsersParams::InvalidUsersTypes typeBefore,
                         InvalidUsersParams::InvalidUsersTypes typeAfter);
            bool handle();
        private:
            UsersParams invalidDDoSUsersParams;
            UsersParams invalidMaliciousUsersParams;
        };

        UsersTypes get (IPAddressV4,
                    std::map<IPAddressV4, ValidUsersParams>::iterator &,
                    std::map<IPAddressV4, InvalidUsersParams>::iterator &);
        void insert (IPAddressV4 ipAddr);
        void update();

        Statistics getStatistics()
        {
            return statistics;
        }
        void resetStatistics() {
            statistics.reset();
        }

    private:
        std::map<IPAddressV4, ValidUsersParams> validUsers;
        std::map<IPAddressV4, InvalidUsersParams> invalidUsers;
        static Statistics statistics;
    } static users;

    class Params {
    public:
        struct DynamicNumbers {
            size_t min;
            size_t cur;
            size_t max;
        };
        DynamicNumbers validAvgConnNumber;  // k
        DynamicNumbers validPacketNumber;   // n
        void init();
        QTimer* UpdateValidAvgConnTimer; // TODO
        static const time_t UPDATE_VALID_AVG_CONN_TIMER_INTERVAL = 1000;

    private:
        static const size_t VALID_AVG_CONN_NUMBER_MIN = 7;
        static const size_t VALID_AVG_CONN_NUMBER_MAX = 13;
        static const size_t VALID_PACKET_NUMBER_MIN = 3;
        static const size_t VALID_PACKET_NUMBER_MAX = 7;
    } static params;

    class FlowHandler {
    public:
        static void setNormalTimeouts (Flow* flow);
        static void setShortTimeouts (Flow* flow);

    private:
        static const uint16_t NORMAL_HARD_TIMEOUT = 600;
        static const uint16_t NORMAL_IDLE_TIMEOUT = 60;
        static const uint16_t SHORT_HARD_TIMEOUT = 60;
        static const uint16_t SHORT_IDLE_TIMEOUT = 10;
    };

private slots:
    void DetectDDoSTimeout();
//    void UpdateValidAvgConnTimeout();
//    void ClearInvalidUsersTimeout();
};