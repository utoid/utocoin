// Copyright (c) 2025 The Utocoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef UTOCOIN_UTOCOIN_TEST_FIXTURE_H
#define UTOCOIN_UTOCOIN_TEST_FIXTURE_H

#include <test/util/setup_common.h>
#include <random>
#include <type_traits>
#include <limits>

namespace utocoin {

struct UtocoinTestingSetup : public TestingSetup {
    explicit UtocoinTestingSetup(const ChainType chain_type = ChainType::MAIN);
    ~UtocoinTestingSetup();
};

std::vector<unsigned char> random_vector(int max_length = 128);
std::vector<unsigned char> random_fixed_vector(int length = 32);

std::time_t now_timestamp();

template<std::integral T>
T randomInt(T min = std::numeric_limits<T>::min(), T max = std::numeric_limits<T>::max())
{
    static thread_local std::mt19937_64 engine{std::random_device{}()};
    std::uniform_int_distribution<uint64_t> dist(
        static_cast<uint64_t>(min),
        static_cast<uint64_t>(max)
    );
    return static_cast<T>(dist(engine));
}

}

#endif // UTOCOIN_UTOCOIN_TEST_FIXTURE_H