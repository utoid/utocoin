// Copyright (c) 2025 The Utocoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utocoin_test_fixture.h"

#include <random>
#include <chrono>

namespace utocoin {

UtocoinTestingSetup::UtocoinTestingSetup(const ChainType chain_type) {}

UtocoinTestingSetup::~UtocoinTestingSetup() {}

std::vector<unsigned char> random_vector(int max_length)
{
    std::mt19937 rng(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<int> length_dist(1, max_length);
    std::uniform_int_distribution<int> value_dist(0, 255);
    int random_length = length_dist(rng);

    std::vector<unsigned char> random_vec(random_length);
    for (int i = 0; i < random_length; ++i) {
        random_vec[i] = static_cast<unsigned char>(value_dist(rng));
    }
    return random_vec;
}

std::vector<unsigned char> random_fixed_vector(int length)
{
    std::mt19937 rng(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<int> value_dist(0, 255);

    std::vector<unsigned char> random_vec(length);
    for (int i = 0; i < length; ++i) {
        random_vec[i] = static_cast<unsigned char>(value_dist(rng));
    }
    return random_vec;
}

std::time_t now_timestamp()
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    return now_c;
}

} // namespace utocoin
