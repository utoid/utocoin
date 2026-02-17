// Copyright (c) 2025 The Utocoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "utocoin/test/utocoin_test_fixture.h"
#include <boost/test/unit_test.hpp>
#include <primitives/block.h>
#include <crypto/scrypt.h>
#include <chrono>
#include <ctime>

using namespace std;
using namespace util::hex_literals;

namespace utocoin::test {
// static uint256 random_uint256()
// {
//     vector<unsigned char> data = random_fixed_vector(32);
//     return uint256{Span{data.data(), data.size()}};
// }

CBlockHeader makeBlockHeader(int32_t nVersion, uint256 hashPrevBlock, uint256 hashMerkleRoot, uint32_t nTime, uint32_t nBits, uint32_t nNonce)
{
    CBlockHeader h;
    h.nVersion = 1;
    h.hashPrevBlock = hashPrevBlock;
    h.hashMerkleRoot = hashMerkleRoot;
    h.nTime = nTime;
    h.nBits = nBits;
    h.nNonce = nNonce;
    return h;
}

void dump_block_header(const CBlockHeader &header)
{
#define DUMP_FIELD(x) std::cout << #x << ": " << header.x << std::endl;

    std::cout << "============================== dump block header begin ==============================" << std::endl;
    std::cout << "------------------------------ hash ------------------------------" << std::endl;
    std::cout << "hash(sha256&sha256): " << header.GetHash().ToString() << std::endl;
    std::cout << "hash(scrypt): " << header.GetScryptHash().ToString() << std::endl;
    std::cout << "------------------------------ header bytes ------------------------------" << std::endl;
    std::cout << "header bytes: " << HexStr((ScryptHashWriter{} << header).Data()) << std::endl;
    std::cout << "------------------------------ header content ------------------------------" << std::endl;
    DUMP_FIELD(nVersion);
    DUMP_FIELD(hashPrevBlock);
    DUMP_FIELD(hashMerkleRoot);
    DUMP_FIELD(nTime);
    DUMP_FIELD(nBits);
    DUMP_FIELD(nNonce);
    std::cout << "============================== dump block header end ==============================" << std::endl;

}

BOOST_FIXTURE_TEST_SUITE(scrypt_pow_tests, UtocoinTestingSetup)

// BOOST_AUTO_TEST_CASE(test_scrypt_pow)
// {
//     static uint256 null_hash;
//     null_hash.SetNull();
//
//     CBlockHeader genesisHeader = makeBlockHeader(1, null_hash, random_uint256(),
//                                                  now_timestamp(), randomInt<uint32_t>(), randomInt<uint32_t>());
//     dump_block_header(genesisHeader);
//
//     CBlockHeader header = makeBlockHeader(1, genesisHeader.GetScryptHash(), random_uint256(),
//                                           now_timestamp(), randomInt<uint32_t>(), randomInt<uint32_t>());
//     dump_block_header(header);
// }

BOOST_AUTO_TEST_CASE(test_constant)
{
    uint256 genesisHashPrevBlock;
    genesisHashPrevBlock.SetNull();
    optional<uint256> genesisMerkleRoot = uint256::FromHex("329db577d902b635fd37c5b194d2e379fb8f640191f036a049a18cec0287b6c8");
    optional<uint256> expectedGenesisHash = uint256::FromHex("2926a03d9037bfb5cab5fd9d1192f73189947a3244518345a87114e51803f823");
    optional<uint256> expectedGenesisScryptHash = uint256::FromHex("112714bf70c2bdd4a0a728af0e556856f026a929fe5908880eea26db2a843487");
    std::string expectedGenesisBlockHeadHex = "010000000000000000000000000000000000000000000000000000000000000000000000c8b68702ec8ca149a036f09101648ffb79e3d294b1c537fd35b602d977b59d324b07b0688db3414d578c4c64";
    BOOST_TEST_REQUIRE(genesisMerkleRoot.has_value());
    BOOST_TEST_REQUIRE(expectedGenesisHash.has_value());
    BOOST_TEST_REQUIRE(expectedGenesisScryptHash.has_value());

    CBlockHeader genesisHeader = makeBlockHeader(1, genesisHashPrevBlock, genesisMerkleRoot.value(), 1756366667, 1296151437, 1682738263);
    std::string genesisHeaderHex = HexStr((ScryptHashWriter{} << genesisHeader).Data());
    BOOST_TEST(genesisHeaderHex == expectedGenesisBlockHeadHex);
    BOOST_TEST(expectedGenesisHash.value().Compare(genesisHeader.GetHash()) == 0);
    BOOST_TEST(expectedGenesisScryptHash.value().Compare(genesisHeader.GetScryptHash()) == 0);


    optional<uint256> otherHashPrevBlock = uint256::FromHex("112714bf70c2bdd4a0a728af0e556856f026a929fe5908880eea26db2a843487");
    optional<uint256> otherMerkleRoot = uint256::FromHex("781681d9b85637b63a2c40f2e6a8c96b2086c05076a5fc349eef9c894d592404");
    optional<uint256> expectedOtherHash = uint256::FromHex("b8a6d064be19ac80f735428f7a4e36e6616deecd90d13a681450c8ce649accc6");
    optional<uint256> expectedOtherScryptHash = uint256::FromHex("27658812ad435313d7368f48137dacdaf35e8ec5ded7bb94715336e7ad7b2124");
    std::string expectedOtherBlockHeadHex = "010000008734842adb26ea0e880859fe29a926f05668550eaf28a7a0d4bdc270bf1427110424594d899cef9e34fca57650c086206bc9a8e6f2402c3ab63756b8d98116784b07b0680b162bc6150b2326";
    BOOST_TEST_REQUIRE(otherHashPrevBlock.has_value());
    BOOST_TEST_REQUIRE(genesisMerkleRoot.has_value());
    BOOST_TEST_REQUIRE(expectedGenesisHash.has_value());
    BOOST_TEST_REQUIRE(expectedGenesisScryptHash.has_value());

    CBlockHeader otherHeader = makeBlockHeader(1, otherHashPrevBlock.value(), otherMerkleRoot.value(), 1756366667, 3324712459, 639830805);
    std::string otherHeaderHex = HexStr((ScryptHashWriter{} << otherHeader).Data());
    BOOST_TEST(otherHeaderHex == expectedOtherBlockHeadHex);
    BOOST_TEST(expectedOtherHash.value().Compare(otherHeader.GetHash()) == 0);
    BOOST_TEST(expectedOtherScryptHash.value().Compare(otherHeader.GetScryptHash()) == 0);
}

// BOOST_AUTO_TEST_CASE(test_for_golang)
// {
//     std::string expectedOtherBlockHeadHex = "010000008734842adb26ea0e880859fe29a926f05668550eaf28a7a0d4bdc270bf1427110424594d899cef9e34fca57650c086206bc9a8e6f2402c3ab63756b8d98116784b07b0680b162bc6150b2326";
//     std::vector<unsigned char> bin = ParseHex<unsigned char>(expectedOtherBlockHeadHex);
//     uint256 thash;
//     scrypt_1024_1_1_256((const char *)bin.data(), reinterpret_cast<char*>(thash.begin()));
//     std::cout << "1024: " << thash << std::endl;
//
//     scrypt_32k_1_1_256((const char *)bin.data(), reinterpret_cast<char*>(thash.begin()));
//     std::cout << "32k: " << thash << std::endl;
// }
//
// BOOST_AUTO_TEST_CASE(test_performance)
// {
//     static uint256 null_hash;
//     null_hash.SetNull();
//     CBlockHeader genesisHeader = makeBlockHeader(1, null_hash, random_uint256(),
//                                                      now_timestamp(), randomInt<uint32_t>(), randomInt<uint32_t>());
//     int test_count = 2000;
//
//     auto time1 = std::chrono::system_clock::now();
//     for (int i = 0;i < test_count;i++) {
//         genesisHeader.GetHash();
//     }
//     auto time2 = std::chrono::system_clock::now();
//     for (int i = 0;i < test_count;i++) {
//         genesisHeader.GetScryptHash();
//     }
//     auto time3 = std::chrono::system_clock::now();
//
//     auto time1_duration = std::chrono::duration_cast<std::chrono::milliseconds>(time1.time_since_epoch()).count();
//     auto time2_duration = std::chrono::duration_cast<std::chrono::milliseconds>(time2.time_since_epoch()).count();
//     auto time3_duration = std::chrono::duration_cast<std::chrono::milliseconds>(time3.time_since_epoch()).count();
//
//     std::cout << "double sha256 " << test_count << " times: " << time2_duration - time1_duration << " ms" << std::endl;
//     std::cout << "scrypt " << test_count << " times: " << time3_duration - time2_duration << " ms" << std::endl;
// }

BOOST_AUTO_TEST_SUITE_END()

} // namespace utocoin::test