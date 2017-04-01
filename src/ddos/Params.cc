#include "Params.hh"
#include "Users.hh"

void Params::init()
{
    validAvgConnNumber.min = VALID_AVG_CONN_NUMBER_MIN;
    validAvgConnNumber.max = VALID_AVG_CONN_NUMBER_MAX;
    validAvgConnNumber.cur = (VALID_AVG_CONN_NUMBER_MIN + VALID_AVG_CONN_NUMBER_MAX) / 2;
    countK1K2();

    validPacketNumber.min = VALID_PACKET_NUMBER_MIN;
    validPacketNumber.max = VALID_PACKET_NUMBER_MAX;
    validPacketNumber.cur = (VALID_PACKET_NUMBER_MIN + VALID_PACKET_NUMBER_MAX) / 2;
}

void Params::updateValidAvgConnNumber (const Users& users)
{
    size_t avgConnNumber = 0;
    for (auto it = users.validUsers.begin(), end = users.validUsers.end(); it != end; ++it)
    {
        avgConnNumber += it->second.avgConnNumber;
    }
    avgConnNumber = avgConnNumber / (float) users.validUsers.size() + .5;

    validAvgConnNumber.cur = validateValidAvgConnNumber(avgConnNumber);
    countK1K2();
}

size_t Params::validateValidAvgConnNumber(size_t validAvgConnNumber_)
{
//    LOG(INFO) << "ControllerDDoSProtectionParams::validateValidAvgConnNumber()";
    if (validAvgConnNumber_ > validAvgConnNumber.min && validAvgConnNumber_ < validAvgConnNumber.max)
    {
        return validAvgConnNumber_;
    }
//    LOG(WARNING) << "Update of Valid Average Connection Number is failed: validAvgConnNumber = " << validAvgConnNumber_;
    return validAvgConnNumber.cur;
}

void Params::countK1K2()
{
    size_t j = countJ();
    validAvgConnNumber.k1 = validAvgConnNumber.cur + (j/2 + 1/2);
    validAvgConnNumber.k2 = validAvgConnNumber.cur - (j/2 + 1/2);
}
