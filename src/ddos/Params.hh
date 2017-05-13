#pragma once

#include <cstddef>
#include <ctime>
#include <cmath>

#include <glog/logging.h>

class Users;

class Params {
public:
    struct DynamicNumbers {
        size_t min;
        size_t cur; // lambda
        size_t max;
    };
    struct DynamicNumbers2 : public DynamicNumbers {
        size_t k1; // k1 = lambda - i (2j)
        size_t k2; // k2 = lambda + i
    };
    Params (double x_ = X): x(x_) {}
    void init();

    // --> Malicious
    inline bool isInvalidConnNumber (size_t connNumber) const { return connNumber >= validAvgConnNumber.k2; }

    // --> Valid
    inline bool isValidConnNumber (size_t connNumber) const { return connNumber >= validAvgConnNumber.k1; }

    inline bool isInvalidPacketNumber (size_t packetNumber) const { return packetNumber < validPacketNumber.cur; }
    void updateValidAvgConnNumber (const Users& users);
    size_t validateValidAvgConnNumber (size_t validAvgConnNumber_);
    DynamicNumbers getValidPacketNumber() { return validPacketNumber; }
    void print();

private:
    void countK1K2();
    size_t countJ()
    {
        // x = sum(j = 0; j < 2i; ++j) (e^(-lambda) * lambda^j / j!)
        size_t j = 0;
        double lambda = validAvgConnNumber.cur;
        double y = x / std::exp(-lambda);
        for (double ret = poisscdf(j, lambda), sum = ret; sum < y ; ++j)
        {
            ret = poisscdf(j, lambda, ret);
            sum += ret;
        }
        return j;
    }

    double poisscdf (size_t j, double lambda, double ret_j_1 = 1.0)
    {
        // ret_j-1 = lambda^(j-1) / (j - 1)!
        return ret_j_1 * lambda / factorial(j);
    }

    inline size_t factorial (size_t j) {
        return j == 0 ? 1 : j;
    }

    DynamicNumbers2 validAvgConnNumber;  // k
    DynamicNumbers validPacketNumber;   // n
    const double x; // tolerance for accuracy (percent)

    static constexpr double X = 0.5; // %
    static const size_t VALID_AVG_CONN_NUMBER_MIN = 3; // test(!) data
    static const size_t VALID_AVG_CONN_NUMBER_MAX = 7; // test(!) data
    static const size_t VALID_PACKET_NUMBER_MIN = 3; // value of n is not less than 3
    static const size_t VALID_PACKET_NUMBER_MAX = 5;
};

