#pragma once

#include <cstdint>
#include <map>

#include "Params.hh"

class Users {
    typedef uint32_t IPAddressV4;
    friend class Params;

public:
    static const time_t UPDATE_VALID_AVG_CONN_TIMER_INTERVAL = 120; // seconds
    static const time_t CLEAR_INVALID_USERS_TIMER_INTERVAL = 500;   // seconds

    static constexpr double INVALID_FLOW_PERCENT = 0.5;

    enum UsersExceptionTypes {
        IsValid,
        IsInvalid,
        IsUnknown
    };

    enum UsersTypes {
        Valid,
        Invalid,
        Unknown
    };

    class ValidUsersParams;
    class InvalidUsersParams;

    class UsersCheck { /* Reason: maple using */
        friend class ValidUsersParams;
        friend class InvalidUsersParams;
    public:
        UsersCheck (bool _isChecked = false) : isChecked(_isChecked), recheckCounter(0), flowsCounter(0), invalidFlowsCounter(0) {}
        void updateFlowsCounter (bool isInvalidPacketNumber)
        {
            ++flowsCounter;
            if (isInvalidPacketNumber) ++invalidFlowsCounter;
//            LOG(INFO) << invalidFlowsCounter << "\t" << flowsCounter;
        }
        bool getIsChecked() { return isChecked; }
        void reset() { setIsChecked(false); }
        size_t getFlowsCounter() { return flowsCounter; }
    private:
        bool isInvalid() { return invalidFlowsCounter / (float) flowsCounter > INVALID_FLOW_PERCENT; }
        void setIsChecked (bool _isChecked = true)
        {
            isChecked = _isChecked;
            recheckCounter = flowsCounter = invalidFlowsCounter = 0;
        }
        bool isChecked;
        size_t recheckCounter; /* todo */
        size_t flowsCounter;
        size_t invalidFlowsCounter;
    };

    class InvalidUsersParams;

    class ValidUsersParams {
        friend class Params;
    public:
        ValidUsersParams (size_t _connCounter = 1, int _avgConnNumber = NON_AVG_CONN_NUMBER):
            usersCheck(false), connCounter(_connCounter), avgConnNumber(_avgConnNumber), updateConnCounterTime(time(NULL)) { }
        /* todo */
        ValidUsersParams (InvalidUsersParams invalidUsersParams,
                          size_t _connCounter = 1):
            usersCheck(true), connCounter(_connCounter), avgConnNumber(invalidUsersParams.getConnCounter()), updateConnCounterTime(time(NULL)) { }
        void increaseConnCounter (const Params& params);
        bool typeIsChecked() { return usersCheck.getIsChecked(); }
        size_t getConnCounter() { return connCounter; }
        void updatePacketNumber (const Params& params, uint64_t packetNumber)
        {
            usersCheck.updateFlowsCounter (params.isInvalidPacketNumber(packetNumber));
        }
        void updateIsChecked (const Params& params);
        void print();

    private:
        void checkType (const Params& params);
        UsersCheck usersCheck;
        size_t connCounter;
        int avgConnNumber;
        time_t updateConnCounterTime;

        static const int NON_AVG_CONN_NUMBER = -1;
        static const size_t RECHECK_NUMBER = 5;
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
            : type(DDoS), usersCheck(false), connCounter(_connCounter), hardTimeout(_hardTimeout), idleTimeout(_idleTimeout)
        {
            createTime = updateTime = updateConnCounterTime = time(NULL);
        }
        InvalidUsersParams (ValidUsersParams validUsersParams,
                            time_t _hardTimeout = HARD_TIMEOUT,
                            time_t _idleTimeout = IDLE_TIMEOUT)
            : type(Malicious), usersCheck(true), connCounter(validUsersParams.getConnCounter()), hardTimeout(_hardTimeout), idleTimeout(_idleTimeout)
        {
            createTime = updateTime = updateConnCounterTime = time(NULL);
        }
        void increaseConnCounter (const Params& params);
        bool isObsolete()
        {
            time_t now = time(NULL);
            if (now - updateTime >= idleTimeout || now - createTime >= hardTimeout)
                return true;
            return false;
        }
        InvalidUsersTypes getType() { return type; }
        bool typeIsChecked() { return usersCheck.getIsChecked(); }
        size_t getConnCounter() { return connCounter; }
        void updatePacketNumber (const Params& params, uint64_t packetNumber)
        {
            usersCheck.updateFlowsCounter (params.isInvalidPacketNumber(packetNumber));
        }
        void updateIsChecked (const Params& params);
        void print();

    private:
        void checkType (const Params& params);
        void reset (time_t _hardTimeout = HARD_TIMEOUT,
                    time_t _idleTimeout = IDLE_TIMEOUT)
        {
            connCounter = 1;
            hardTimeout = _hardTimeout;
            idleTimeout = _idleTimeout;
            createTime = updateTime = updateConnCounterTime = time(NULL);
            type = DDoS;
            usersCheck.reset();
        }
        InvalidUsersTypes type;
        UsersCheck usersCheck;
        size_t connCounter;
        time_t hardTimeout;
        time_t idleTimeout;
        time_t createTime;
        time_t updateTime;
        time_t updateConnCounterTime;
        static const size_t INVALID_DDOS_AVG_CONN_NUMBER = 2;
        static const time_t HARD_TIMEOUT = 6000;    // seconds
        static const time_t IDLE_TIMEOUT = 600;     // seconds
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
        void increaseCheckedNumber(InvalidUsersParams::InvalidUsersTypes type = InvalidUsersParams::Malicious) {
            ++invalidMaliciousUsersParams.checkedNumber;
        }
        void decreaseCheckedNumber(InvalidUsersParams::InvalidUsersTypes type = InvalidUsersParams::Malicious) {
            --invalidMaliciousUsersParams.checkedNumber;
        }
        bool handle();
        Statistics(): isStable(true) { } /* false by default */
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
        static const size_t INVALID_DDOS_USERS_NUMBER_WEIGHT = 30;

        static const size_t INVALID_DDOS_USERS_NUMBER_OF_INSERT = 50;
        static const size_t INVALID_DDOS_USERS_NUMBER_OF_INSERT_WEIGHT = 70;

        static constexpr float INVALID_DDOS_USERS_NUMBER_OF_CHANGE_TYPE_NUMBER = 0.6f;
        static const size_t INVALID_DDOS_USERS_NUMBER_OF_CHANGE_TYPE_NUMBER_WEIGHT = 30;
    };

    UsersTypes get (IPAddressV4,
                std::map<IPAddressV4, ValidUsersParams>::iterator &,
                std::map<IPAddressV4, InvalidUsersParams>::iterator &);
    void insert (IPAddressV4 ipAddr);
    void invalidate (std::map<IPAddressV4, ValidUsersParams>::iterator);
    void validate (std::map<IPAddressV4, InvalidUsersParams>::iterator);
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
};
