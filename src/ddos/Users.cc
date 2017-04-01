#include "Users.hh"

Users::Statistics Users::statistics;

Users::UsersTypes
Users::get (IPAddressV4 ipAddr,
            std::map<IPAddressV4, ValidUsersParams>::iterator &validUser,
            std::map<IPAddressV4, InvalidUsersParams>::iterator &invalidUser)
{
//    LOG(INFO) << "Users::get(" << AppObject::uint32_t_ip_to_string(ipAddr) << ")";
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

void Users::insert (IPAddressV4 ipAddr)
{
//    LOG(INFO) << "Users::insert(" << AppObject::uint32_t_ip_to_string(ipAddr) << ")";
    InvalidUsersParams invalidUsersParams;
    invalidUsers.insert (std::pair <IPAddressV4, InvalidUsersParams> (ipAddr, invalidUsersParams));
    statistics.update(Statistics::Actions::Insert,
                      InvalidUsersParams::InvalidUsersTypes::None,
                      InvalidUsersParams::InvalidUsersTypes::DDoS);
}

void Users::invalidate(std::map<IPAddressV4, ValidUsersParams>::iterator it)
{
    InvalidUsersParams invalidUsersParams(it->second);
    invalidUsers.insert(std::pair <IPAddressV4, InvalidUsersParams> (it->first, invalidUsersParams));
    validUsers.erase(it);
    statistics.update(Statistics::Actions::Insert,
                      InvalidUsersParams::InvalidUsersTypes::None,
                      InvalidUsersParams::InvalidUsersTypes::Malicious);
}

void Users::update()
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


// Users::ValidUsersParams
void Users::ValidUsersParams::checkType (const Params& params)
{
    // Valid -> Valid or Malicious
    if (params.isInvalidConnNumber(connCounter)
            || (int)connCounter > avgConnNumber)
    {
        statistics.update(Statistics::Actions::ChangeType, InvalidUsersParams::None, InvalidUsersParams::Malicious);
        throw UsersExceptionTypes::IsInvalid;
    }
}

void Users::ValidUsersParams::increaseConnCounter (const Params& params)
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
    checkType(params);
}


// Users::InvalidUsersParams
void Users::InvalidUsersParams::checkType(const Params& params)
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

void Users::InvalidUsersParams::increaseConnCounter (const Params& params)
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
    checkType(params);
}

// Users::Statistics
void Users::Statistics::update(Actions action,
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
//        LOG(ERROR) << "Invalid InvalidUsersParams::InvalidUsersTypes!";
        break;
    }
}

bool Users::Statistics::handle()
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


// Users::Statistics::UsersParams
void Users::Statistics::UsersParams::updateNumbers(Actions action)
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
//        LOG(ERROR) << "Invalid Statistics::Actions!";
        break;
    }
}
