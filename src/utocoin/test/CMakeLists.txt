# Copyright (c) 2025-present The Utocoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

# Do not use generator expressions in test sources because the
# SOURCES property is processed to gather test suite macros.

target_sources(test_utocoin
        PRIVATE
        utocoin_test_fixture.h
        utocoin_test_fixture.cpp
        stake_promise_tests.cpp
        check_data_sig_tests.cpp
        stake_burn_tests.cpp
        scrypt_pow_tests.cpp
)

target_link_libraries(test_utocoin)
