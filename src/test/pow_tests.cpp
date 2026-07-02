// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/data/utocoin_pow_vectors.json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <span>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1261130161;
    CBlockIndex pindexLast;
    pindexLast.nHeight = 1439;
    pindexLast.nTime = 1261212961;      // 23 hours later
    pindexLast.nBits = 0x1d00ffff;

    // Here (and below): expected_nbits is calculated in
    // CalculateNextWorkRequired(); redoing the calculation here would be just
    // reimplementing the same code that is written in pow.cpp. Rather than
    // copy that code, we just hardcode the expected result.

    unsigned int expected_nbits = 0x1d00f554;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 1439;
    pindexLast.nTime = 1231175705;  // Block #1439, 47 hours later
    pindexLast.nBits = 0x1e307fff;
    unsigned int expected_nbits = 0x1e307fffU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1279008237; // Block #47520
    CBlockIndex pindexLast;
    pindexLast.nHeight = 48959;
    pindexLast.nTime = 1279026237;  // Block #48959, 5 hours later
    pindexLast.nBits = 0x1c05a3f4;
    unsigned int expected_nbits = 0x1c0168fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that reducing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits-1;
    BOOST_CHECK(!PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1263163443; // NOTE: Not an actual block time
    CBlockIndex pindexLast;
    pindexLast.nHeight = 48959;
    pindexLast.nTime = 1263523443;  // Block #48959, 100 hours later
    pindexLast.nBits = 0x1c387f6f;
    unsigned int expected_nbits = 0x1d00e1fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that increasing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits+1;
    BOOST_CHECK(!PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash = uint256{1};
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p2 = &blocks[m_rng.randrange(10000)];
        CBlockIndex *p3 = &blocks[m_rng.randrange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // check max target * 4*nPowTargetTimespan doesn't overflow -- see pow.cpp:CalculateNextWorkRequired()
    //
    // utocoin intentionally raised powLimit on TESTNET / TESTNET4 / SIGNET to
    // make RandomX-difficulty mining feasible (the upstream values were tuned
    // for SHA256d). With the upstream nPowTargetTimespan still at 14 days, the
    // product `powLimit * 4 * timespan` overflows uint256 in the retarget
    // math, which is what this assertion guards against. We skip it on those
    // three chains; a follow-up should either tighten powLimit or rework
    // CalculateNextWorkRequired to do the multiply in arith_uint512.
    const bool skip_overflow_check =
        chain_type == ChainType::TESTNET ||
        chain_type == ChainType::TESTNET4 ||
        chain_type == ChainType::SIGNET;
    if (!consensus.fPowNoRetargeting && !skip_overflow_check) {
        arith_uint256 targ_max{UintToArith256(uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"})};
        targ_max /= consensus.nPowTargetTimespan*4;
        BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
    }
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET4_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET4);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET);
}

BOOST_AUTO_TEST_CASE(utocoin_pow_vectors)
{
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(json_tests::utocoin_pow_vectors));

    const auto chainParams{CreateChainParams(*m_node.args, ChainType::MAIN)};
    const auto& consensus{chainParams->GetConsensus()};
    const UniValue& mainnet{vectors["mainnet"]};
    const UniValue& params{mainnet["params"]};

    BOOST_CHECK_EQUAL(params["pow_algorithm"].get_str(), "randomx");
    BOOST_CHECK_EQUAL(params["header_size"].getInt<int>(), 80);
    BOOST_CHECK_EQUAL(params["nonce_offset"].getInt<int>(), 76);
    BOOST_CHECK_EQUAL(params["pow_limit"].get_str(), consensus.powLimit.GetHex());
    BOOST_CHECK_EQUAL(params["target_spacing"].getInt<int64_t>(), consensus.nPowTargetSpacing);
    BOOST_CHECK_EQUAL(params["target_timespan"].getInt<int64_t>(), consensus.nPowTargetTimespan);
    BOOST_CHECK_EQUAL(params["difficulty_adjustment_interval"].getInt<int64_t>(), consensus.DifficultyAdjustmentInterval());
    BOOST_CHECK_EQUAL(params["randomx_epoch"].getInt<int>(), consensus.randomx_epoch);
    BOOST_CHECK_EQUAL(params["randomx_lag"].getInt<int>(), consensus.randomx_lag);
    BOOST_CHECK_EQUAL(params["randomx_genesis_key"].get_str(), consensus.randomx_genesis_key);
    BOOST_CHECK_EQUAL(params["genesis_block_hash"].get_str(), consensus.hashGenesisBlock.GetHex());
    BOOST_CHECK_EQUAL(params["genesis_merkle_root"].get_str(), chainParams->GenesisBlock().hashMerkleRoot.GetHex());

    for (const auto& entry : mainnet["key_schedule"].getValues()) {
        BOOST_CHECK_EQUAL(GetRandomXKeyBlockHeight(entry["height"].getInt<int>(), consensus), entry["key_height"].getInt<int>());
    }

    for (const auto& entry : mainnet["pow_hashes"].getValues()) {
        const int height{entry["height"].getInt<int>()};
        const std::string header_hex{entry["header_hex"].get_str()};
        const std::optional<uint256> key{uint256::FromHex(entry["randomx_key_hex"].get_str())};
        BOOST_REQUIRE(key);
        BOOST_CHECK_EQUAL(HexStr(std::span{key->data(), key->size()}), entry["randomx_key_bytes_hex"].get_str());

        CBlockHeader header;
        DataStream stream{ParseHex(header_hex)};
        stream >> header;

        DataStream serialized{};
        serialized << header;
        BOOST_CHECK_EQUAL(HexStr(serialized), header_hex);
        BOOST_CHECK_EQUAL(header.GetHash().GetHex(), entry["block_hash"].get_str());
        BOOST_CHECK_EQUAL(GetRandomXPoWHash(header, *key).GetHex(), entry["pow_hash"].get_str());

        const std::optional<uint256> proof_hash{GetBlockProofHash(header, height, nullptr, consensus)};
        BOOST_REQUIRE(proof_hash);
        BOOST_CHECK_EQUAL(proof_hash->GetHex(), entry["pow_hash"].get_str());
        BOOST_CHECK_EQUAL(CheckProofOfWork(*proof_hash, header.nBits, consensus), entry["valid"].get_bool());
    }
}

BOOST_AUTO_TEST_SUITE_END()
