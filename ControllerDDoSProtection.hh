#pragma once

#include <mutex>

#include "Application.hh"
#include "OFMessageHandler.hh"
#include "ILinkDiscovery.hh"
#include "Controller.hh"
#include "Switch.hh"

// EtherType
#define IPv4_TYPE 0x0800
#define IPv6_TYPE 0x86DD

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

    QTimer* detectDDoSTimer;
    static const size_t DETECT_DDOS_TIMER_INTERVAL = 5;

    QTimer* updateValidAvgConnTimer;
    static const time_t UPDATE_VALID_AVG_CONN_TIMER_INTERVAL = 100;

    QTimer* clearInvalidUsersTimer;
    static const size_t CLEAR_INVALID__USERS_TIMER_INTERVAL = 500;

    static constexpr float INVALID_FLOW_PERCENT = 0.1;

    OFTransaction* pdescr;

    class Params;

    class Users {
        friend class Params;
    public:
        enum UsersExceptionTypes {
            IsValid,
            IsUnknown
        };

        enum UsersTypes {
            Valid,
            Invalid,
            Unknown
        };

        class ValidUsersParams {
            friend class Params;
        public:
            ValidUsersParams (size_t _connCounter = 1, int _avgConnNumber = NON_AVG_CONN_NUMBER):
                isChecked(true), connCounter(_connCounter), avgConnNumber(_avgConnNumber), updateConnCounterTime(time(NULL)) { }
            void increaseConnCounter();
            bool typeIsChecked() { return isChecked; }
            size_t getConnCounter() { return connCounter; }
        private:
            void checkType();
            bool isChecked;
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
                : type(DDoS), isChecked(false), connCounter(_connCounter), hardTimeout(_hardTimeout), idleTimeout(_idleTimeout)
            {
                createTime = updateTime = updateConnCounterTime = time(NULL);
            }
            InvalidUsersParams (ValidUsersParams validUsersParams,
                                time_t _hardTimeout = HARD_TIMEOUT,
                                time_t _idleTimeout = IDLE_TIMEOUT)
                : type(Malicious), isChecked(true), connCounter(validUsersParams.getConnCounter()), hardTimeout(_hardTimeout), idleTimeout(_idleTimeout)
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
            bool typeIsChecked() { return isChecked; }
            void check() { isChecked = true; }
        private:
            void checkType();
            void reset (time_t _hardTimeout = HARD_TIMEOUT,
                        time_t _idleTimeout = IDLE_TIMEOUT)
            {
                connCounter = 1;
                hardTimeout = _hardTimeout;
                idleTimeout = _idleTimeout;
                createTime = updateTime = updateConnCounterTime = time(NULL);
                type = DDoS;
                isChecked = false;
            }
            InvalidUsersTypes type;
            bool isChecked;
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
                UsersParams() : number(0), checkedNumber(0), numberOfChanges() { }
                void reset()
                {
                    // numbers are not reset
                    numberOfChanges.clear();
                }
                void updateNumbers(Actions action);
                size_t number;
                size_t checkedNumber;
                struct NumberOfActions {
                    size_t reset;
                    size_t insert;
                    size_t changeType;
                    size_t update;
                    size_t remove;
                    NumberOfActions(): reset(0), insert(0), changeType(0), update(0), remove(0) { }
                    void clear()
                    {
                        reset = insert = changeType = update = remove = 0;
                    }
                };
                NumberOfActions getNumberOfChanges()
                {
                    return numberOfChanges;
                }
            private:
                 NumberOfActions numberOfChanges;
            };
            void reset()
            {
                // isStable flag is not reset
                invalidDDoSUsersParams.reset();
                invalidMaliciousUsersParams.reset();
            }
            void update (Actions action,
                         InvalidUsersParams::InvalidUsersTypes typeBefore,
                         InvalidUsersParams::InvalidUsersTypes typeAfter);
            bool handle();
            Statistics(): isStable(false) { }
        private:
            UsersParams invalidDDoSUsersParams;
            UsersParams invalidMaliciousUsersParams;
            bool isStable;
            static const size_t IS_DDOS_WEIGHT = 100;

            static const size_t INVALID_MALICIOUS_USERS_CHECKED_NUMBER = 1;
            static const size_t INVALID_MALICIOUS_USERS_CHECKED_NUMBER_WEIGHT = 100;

            static const size_t INVALID_MALICIOUS_USERS_NUMBER_OF_CHANGE_TYPE = 5;
            static const size_t INVALID_MALICIOUS_USERS_NUMBER_OF_CHANGE_TYPE_WEIGHT = 30;

            static constexpr float IS_STABLE_CRITERIA = 0.2f;

            static const size_t INVALID_DDOS_USERS_NUMBER = 100;
            static const size_t INVALID_DDOS_USERS_NUMBER_WEIGHT = 20;

            static const size_t INVALID_DDOS_USERS_NUMBER_OF_INSERT = 50;
            static const size_t INVALID_DDOS_USERS_NUMBER_OF_INSERT_WEIGHT = 50;

            static constexpr float INVALID_DDOS_USERS_NUMBER_OF_CHANGE_TYPE_NUMBER = 0.6f;
            static const size_t INVALID_DDOS_USERS_NUMBER_OF_CHANGE_TYPE_NUMBER_WEIGHT = 30;
        };

        UsersTypes get (IPAddressV4,
                    std::map<IPAddressV4, ValidUsersParams>::iterator &,
                    std::map<IPAddressV4, InvalidUsersParams>::iterator &);
        void insert (IPAddressV4 ipAddr);
        void invalidate (std::map<IPAddressV4, ValidUsersParams>::iterator);
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
//        std::mutex validUsersLock; /* todo */
        std::map<IPAddressV4, InvalidUsersParams> invalidUsers;
//        std::mutex invalidUsersLock; /* todo */
        static Statistics statistics;
    } static users;

    class Params {
    public:
        struct DynamicNumbers {
            size_t min;
            size_t cur;
            size_t max;
        };
        void init();
        inline bool isInvalidConnNumber (size_t connNumber) { return connNumber >= validAvgConnNumber.cur; }
        inline bool isInvalidPacketNumber (size_t packetNumber) { return packetNumber < validPacketNumber.cur; }
        void updateValidAvgConnNumber();
        size_t validateValidAvgConnNumber(size_t validAvgConnNumber_);
    private:
        DynamicNumbers validAvgConnNumber;  // k
        DynamicNumbers validPacketNumber;   // n

        static const size_t VALID_AVG_CONN_NUMBER_MIN = 7;
        static const size_t VALID_AVG_CONN_NUMBER_MAX = 13;
        static const size_t VALID_PACKET_NUMBER_MIN = 3;
        static const size_t VALID_PACKET_NUMBER_MAX = 7;
    } static params;

    class FlowHandler {
    public:
        inline static void setNormalTimeouts (Flow* flow);
        inline static void setShortTimeouts (Flow* flow);

    private:
        static const uint16_t NORMAL_HARD_TIMEOUT = 300;
        static const uint16_t NORMAL_IDLE_TIMEOUT = 60;
        static const uint16_t SHORT_HARD_TIMEOUT = 60;
        static const uint16_t SHORT_IDLE_TIMEOUT = 10;
    };
signals:
    void UsersTypeChanged (IPAddressV4 ipAddr, OFConnection *ofconn);
private slots:
    void detectDDoSTimeout();
    void updateValidAvgConnTimeout();
    void clearInvalidUsersTimeout();
    void getUsersStatistics (IPAddressV4 ipAddr, OFConnection *ofconn);
    void usersStatisticsArrived (OFConnection* ofconn, std::shared_ptr<OFMsgUnion> reply);
};
