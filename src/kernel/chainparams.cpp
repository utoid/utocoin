// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

using namespace util::hex_literals;

// Workaround MSVC bug triggering C7595 when calling consteval constructors in
// initializer lists.
// A fix may be on the way:
// https://developercommunity.visualstudio.com/t/consteval-conversion-function-fails/1579014
#if defined(_MSC_VER)
auto consteval_ctor(auto&& input) { return input; }
#else
#define consteval_ctor(input) (input)
#endif

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const std::vector<CTransactionRef> &txs)
{
    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx = txs;
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}


static CBlock CreateGenesisBlock(const char* pszTimestamp, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const std::vector<CTxOut> &genesisRewards)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout = genesisRewards;

    return CreateGenesisBlock(nTime, nNonce, nBits, nVersion, {MakeTransactionRef(std::move(txNew))});
}

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    return CreateGenesisBlock(pszTimestamp, nTime, nNonce, nBits, nVersion, {CTxOut{genesisReward, genesisOutputScript}});
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript = CScript() << "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"_hex << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

class CGenesisBlock
{
public:
    virtual ~CGenesisBlock() {};
    virtual CBlock Create() = 0;
    virtual const uint256 &BlockHash() = 0;
    virtual const uint256 &MerkleRoot() = 0;
};

class CRegTestGenesisBlock : public CGenesisBlock
{
    static constexpr uint256 hashGenesisBlock = uint256{"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"};
    static constexpr uint256 hashMerkleRoot = uint256{"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"};

public:
    CBlock Create() override
    {
        return CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
    }
    const uint256& BlockHash() override
    {
        return hashGenesisBlock;
    }
    const uint256& MerkleRoot() override
    {
        return hashMerkleRoot;
    }
};

class CRegTestGenesisBlockScrypt : public CGenesisBlock
{
    static constexpr uint256 hashGenesisBlock = uint256{"7c689a1b2cdee9b1c2e79e08ba2414bb6e0f611c505a677917fc6b4b61aab4cd"};
    static constexpr uint256 hashMerkleRoot = uint256{"4203186caf064e409b33811613274d2880e5f456b390b60596dd1b663d640073"};
    // Use this private key to unlock output[2] who is a p2pkh script
    static constexpr std::string_view privkey = "6334dc1f7baa091f3ca23252bec38023ccc90cd25accda86561cb80e2c914941";

public:
    CBlock Create() override
    {
        const char* genesis_msg = "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e";
        uint32_t nTime = 1296688602;
        uint32_t nNounce = 1073741823;
        uint32_t nBits = 0x207fffff;
        std::vector<CTransactionRef> txs;
        CMutableTransaction txCoinBase;

        txCoinBase.version = 1;
        txCoinBase.vin.resize(1);
        txCoinBase.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)genesis_msg, (const unsigned char*)genesis_msg + strlen(genesis_msg));

        {
            auto scriptData = "51"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10000000000, script);
        }
        {
            auto scriptData = "5187"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(100000000000, script);
        }
        {
            auto scriptData = "76a91469b7242b4dd0731ffb217844e6936b7243e9df7188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(1000000000000, script);
        }

        CBlock block = CreateGenesisBlock(
                nTime,
                nNounce,
                nBits,
                1,
                {MakeTransactionRef(std::move(txCoinBase))});
        assert(block.GetHash() == BlockHash());
        assert(block.hashMerkleRoot == MerkleRoot());
        return block;
    }

    const uint256& BlockHash() override
    {
        return hashGenesisBlock;
    }

    const uint256& MerkleRoot() override
    {
        return hashMerkleRoot;
    }
};

class CTestNet4GenesisBlock : public CGenesisBlock
{
    static constexpr uint256 hashGenesisBlock = uint256{"f2911aa9a5c75628271110e28073bd2553953d96e3f5116eb80bed53c881c99f"};
    static constexpr uint256 hashMerkleRoot = uint256{"e8ef3dd1314380b081743a1fc2252324513f1f1797d30067bf495833732b6f26"};
public:
    CBlock Create() override
    {
        const char* genesis_msg = "2025 utocoin premined";
        uint32_t nTime = 1763479202;
        uint32_t nNounce = 715867345;
        uint32_t nBits = 0x1e307fff;
        std::vector<CTransactionRef> txs;
        CMutableTransaction txCoinBase;

        txCoinBase.version = 1;
        txCoinBase.vin.resize(1);
        txCoinBase.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)genesis_msg, (const unsigned char*)genesis_msg + strlen(genesis_msg));

        {
            auto scriptData = "76a914096764b502a9c333b6a61fb6d7791480747bd11188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(50000000000, script);
        }
        {
            auto scriptData = "0014096764b502a9c333b6a61fb6d7791480747bd111"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(100300000000, script);
        }

        CBlock block = CreateGenesisBlock(
                nTime,
                nNounce,
                nBits,
                1,
                {MakeTransactionRef(std::move(txCoinBase))});
        assert(block.GetHash() == BlockHash());
        assert(block.hashMerkleRoot == MerkleRoot());
        return block;
    }
    const uint256& BlockHash() override
    {
        return hashGenesisBlock;
    }
    const uint256& MerkleRoot() override
    {
        return hashMerkleRoot;
    }
};

class CMainNetGenesisBlock : public CGenesisBlock
{
    static constexpr uint256 hashGenesisBlock = uint256{"c7f9a3589fee6ce463838d54f891a45c4d3cdb970edb9748ff9db6cf2d8a9cc2"};
    static constexpr uint256 hashMerkleRoot = uint256{"acb0e4822248093629b95124539508a08984cd0bd18204e941b5a6ec3742ef4f"};
public:
    CBlock Create() override
    {
        const char* genesis_msg = "bitcoin/936960/00000000000000000000973ae0ee999c557d8a9aebab13ef96ac6fdb655bd76b";
        uint32_t nTime = 1771271580;
        uint32_t nNounce = 1431664606;
        uint32_t nBits = 0x1e307fff;
        std::vector<CTransactionRef> txs;
        CMutableTransaction txCoinBase;

        txCoinBase.version = 1;
        txCoinBase.vin.resize(1);
        txCoinBase.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)genesis_msg, (const unsigned char*)genesis_msg + strlen(genesis_msg));

        {
            auto scriptData = "03200508b17576a9144d4042e31ab2c3476b116b7a33e38bf30fda449b88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(19950700000000, script);
        }
        {
            auto scriptData = "03200508b17576a9149ed3117e3d427659392395c668ff3a0a839386d888ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8511400000000, script);
        }
        {
            auto scriptData = "03200508b17576a9149c4bdf53862632fa30bff83736c5faf778b5723a88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(19786400000000, script);
        }
        {
            auto scriptData = "03200508b17576a9148c7ff76eb1243a86b4906b4875235d5fd0f4a4d288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7274800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914068923bd46cd1142de8583d77337c7bd1ddce7ef88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(3571200000000, script);
        }
        {
            auto scriptData = "03200508b17576a91420af224b8b8791381cacc07e2ba1d491bb853d7988ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5189000000000, script);
        }
        {
            auto scriptData = "03200508b17576a914e69f5bbd3d16df6a9014e988e1a6a4516369dd5e88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(19653500000000, script);
        }
        {
            auto scriptData = "03200508b17576a91443d8728b101378333db3d3240b1251519bbf35eb88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(20040700000000, script);
        }
        {
            auto scriptData = "03200508b17576a91472bd575b35960f5d8a1c3534c9e33bc28957a8d988ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(14612900000000, script);
        }
        {
            auto scriptData = "03200508b17576a914e38cd5655f0f2f1e28fe3213268bbfae1879dc4d88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(19625200000000, script);
        }
        {
            auto scriptData = "03200508b17576a914408561f360db9672398e585aa30f2210ba5b29bc88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(13744600000000, script);
        }
        {
            auto scriptData = "03200508b17576a914c718dcb8fcc20dd0e49a061789d346bb0e2adc5d88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(12913200000000, script);
        }
        {
            auto scriptData = "03200508b17576a91480e1e7fedcc721735b25f755086d1bc9ae14acb788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10803100000000, script);
        }
        {
            auto scriptData = "03200508b17576a914259ca76105e2882f01b2afef28a08c5450532d2388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(14400400000000, script);
        }
        {
            auto scriptData = "03200508b17576a914ad276cd423b2b974d2bd91b1c66db2102fe6f32788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(15529100000000, script);
        }
        {
            auto scriptData = "03200508b17576a914632d971c308030a74c688ab78882cb01253de16788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7246800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914d0903b6a13eb950eb74e9b5b97229cfb4bc77f3688ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(12318900000000, script);
        }
        {
            auto scriptData = "03200508b17576a914dcbc6d57f3d50df6b92ad0df3e8156f84780646288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(16674100000000, script);
        }
        {
            auto scriptData = "03200508b17576a9140f5a7077623a591dea560fe2fb3e2eec198c2b1f88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8706000000000, script);
        }
        {
            auto scriptData = "03200508b17576a914ff5bd0952381d51fdb829395899256a4ee585c4f88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(13631600000000, script);
        }
        {
            auto scriptData = "03200508b17576a9148fc207dd0af18571107eba39bf58c04ccd8823ed88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8130100000000, script);
        }
        {
            auto scriptData = "03200508b17576a91478d5bb760c397bf9512089be3618cfc56ca99d3188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(16086600000000, script);
        }
        {
            auto scriptData = "03200508b17576a914bc747b1bf5bac2ecf84b8c2ddf4eb2cf6404648588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10447500000000, script);
        }
        {
            auto scriptData = "03200508b17576a91478852af231f71d2019d2cbdd7fca377ebce4086788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(2518300000000, script);
        }
        {
            auto scriptData = "03200508b17576a9146eea116c5ec1f736f5cbbccfe38a5ebb7ffbd3b088ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(2843300000000, script);
        }
        {
            auto scriptData = "03200508b17576a9149c75cab6259969adc3c64ab6df54ed8648553f2a88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(16017100000000, script);
        }
        {
            auto scriptData = "03200508b17576a914be96af5b4dc6b3274df0cfb496c893a5a594cb9c88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(9606400000000, script);
        }
        {
            auto scriptData = "03200508b17576a91491a6fc5700a965a312265e6b941e218a6808746588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11872000000000, script);
        }
        {
            auto scriptData = "03200508b17576a9141cd4e7b2bea77f07f6341ee678e5b3048c87009a88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(19499000000000, script);
        }
        {
            auto scriptData = "03200508b17576a914a25370991641b97d1ad518662b131ced87d4619688ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(19778800000000, script);
        }
        {
            auto scriptData = "03200508b17576a9148b738e9e79a6f12e4b79eb4108a326e785d8475888ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4093600000000, script);
        }
        {
            auto scriptData = "03200508b17576a9145f8b3e624edf16e36284065d0b3533130951d31188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7276900000000, script);
        }
        {
            auto scriptData = "03200508b17576a914123cb4d0cc576df750ef1b137c43b33bcad2bb3288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(18355200000000, script);
        }
        {
            auto scriptData = "03200508b17576a914471cb54476bc8f400bc05570050a99bafc58dd0488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8683700000000, script);
        }
        {
            auto scriptData = "03200508b17576a9147a840d368550a893bdcbdd3a676ffc6076cbf40a88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7784400000000, script);
        }
        {
            auto scriptData = "03200508b17576a9148feefe003352d00ae62f798b06fd23743c8467e088ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(2531600000000, script);
        }
        {
            auto scriptData = "03200508b17576a91406a5d955043b34c11c8beea96e275c7470e87cff88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10290400000000, script);
        }
        {
            auto scriptData = "03200508b17576a914c604c9c633c88820fb10836f799e133db811fc0588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11656500000000, script);
        }
        {
            auto scriptData = "03200508b17576a91418d5e0e563889aa5e774da898f9a878a839db48488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(19818300000000, script);
        }
        {
            auto scriptData = "03200508b17576a9144fd8be9c6e51101331a626f9976a751c506dc75188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6615800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914f738d760c8edc3e42167671b002f731545c5ce4088ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8293200000000, script);
        }
        {
            auto scriptData = "03200508b17576a914af00f678d3b001d99fde358fab5b6817f4dd7b6488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(14048400000000, script);
        }
        {
            auto scriptData = "03200508b17576a9143859dace3eec11644d36f7356e68f79e716f30bc88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(9812900000000, script);
        }
        {
            auto scriptData = "03200508b17576a91427b890e209fa29793789f09f26c77a65853ab6e088ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(12383500000000, script);
        }
        {
            auto scriptData = "03200508b17576a9140a4d4677da50411d6aa0f63a89e7a24957dd396d88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10281700000000, script);
        }
        {
            auto scriptData = "03200508b17576a9142f58789c18c3020769f63f3f27968b2b303164e688ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(9442600000000, script);
        }
        {
            auto scriptData = "03200508b17576a914dacd596f0c0b604bfa623a24b68a5fc3f89fcf2688ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(18711100000000, script);
        }
        {
            auto scriptData = "03200508b17576a914ddf00ffb6a838a4f8b5bc229362f1c7ac8f8debf88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6502500000000, script);
        }
        {
            auto scriptData = "03200508b17576a914c12e3aebb7225a95f23265896d182fa4235df93988ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5296500000000, script);
        }
        {
            auto scriptData = "03200508b17576a914b5e52c47976d4d999f686c62f9370f210f8d1b5c88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4155300000000, script);
        }
        {
            auto scriptData = "03200508b17576a914aed50af1ef2b10d762b8d852f1d3fe7df159839088ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10221800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914deb2fae3f850ad5842a76d4137910e6d03d5f29488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(13197300000000, script);
        }
        {
            auto scriptData = "03200508b17576a914184626f5158a3f8529ad3e8cca647c7b9d1e631588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5762800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914ddb02039b1ab28786b770f516977e761a2710d8a88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(9235800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914a6af4a743320fc6daada6aa87115979f57fd37e588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(9302600000000, script);
        }
        {
            auto scriptData = "03200508b17576a914b212e98b3783a0a05ae107760b64da35b009e34c88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(16268700000000, script);
        }
        {
            auto scriptData = "03200508b17576a91467f03ab85253458488e2f64922a44e11885e9c0788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(14333800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914a5183889e930fb0dbdf84f2dcc64ba7aaaedccab88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10589200000000, script);
        }
        {
            auto scriptData = "03200508b17576a9144066bdab3474bf8156b6601469c44349816ce17288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11664400000000, script);
        }
        {
            auto scriptData = "03200508b17576a914de920dfd3854960f51ea80ffa832a5f1e39948c388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6160200000000, script);
        }
        {
            auto scriptData = "03200508b17576a914fe33e9f3e57a68f67a284a7b64d6002ce6f06e8d88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(9772600000000, script);
        }
        {
            auto scriptData = "03200508b17576a9148e73944f2084fb9cd70448341162c27680f775c788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(2691700000000, script);
        }
        {
            auto scriptData = "03200508b17576a9146332997ec5734acf9016dbfc3f8e641f0126875288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4141600000000, script);
        }
        {
            auto scriptData = "03200508b17576a914d47d9bd8e7b65e0fad851a6761114fd370734bfd88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7752800000000, script);
        }
        {
            auto scriptData = "03200508b17576a9141e18c4bc30480c96de0d9feb1104693212eeb0ab88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(9059100000000, script);
        }
        {
            auto scriptData = "03200508b17576a9142532a91b2832c975b89979fc2f494739d7f01e5f88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10432700000000, script);
        }
        {
            auto scriptData = "03200508b17576a9146593ab4b04dd31e48985c12c8eb7894ffc43128788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(12025600000000, script);
        }
        {
            auto scriptData = "03200508b17576a9146a6ae4dfdda72af0ffc810ac274e104a756260fb88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(16029100000000, script);
        }
        {
            auto scriptData = "03200508b17576a91475f4ae209b52eb4d69cde94e4ce1bb1c7177844488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5789200000000, script);
        }
        {
            auto scriptData = "03200508b17576a9144fda2e35d55e84250b52f78b4626dfccce7992af88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5794300000000, script);
        }
        {
            auto scriptData = "03200508b17576a9147811b021c721723b8febdfbb3e0ab4e5e8383ed388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8779200000000, script);
        }
        {
            auto scriptData = "03200508b17576a914f74eb1fd0716b100d10c2a1e08f4e514ca8903e988ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10238000000000, script);
        }
        {
            auto scriptData = "03200508b17576a914c9eda7039a8cca64eeef6a220baa8dd0c67f31bf88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10914200000000, script);
        }
        {
            auto scriptData = "03200508b17576a9149b85015cf410d9ddef70925ee1484dc87941ef5488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11485700000000, script);
        }
        {
            auto scriptData = "03200508b17576a914a3b628525b0fe8bfb43b973f31583d59786a73d888ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6809800000000, script);
        }
        {
            auto scriptData = "03200508b17576a9147a188a7ee850f4c8a5dec44e2e67236f955716a488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10267700000000, script);
        }
        {
            auto scriptData = "03200508b17576a9143e1d5c3504426ec3ed94bea8e9987a91df1f20c088ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8128200000000, script);
        }
        {
            auto scriptData = "03200508b17576a9146f125e1ef2a1be415cbf4200bb203253c08982b988ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11372000000000, script);
        }
        {
            auto scriptData = "03200508b17576a914c3021e4e8b310235bed793438deba354ba9f501a88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5095600000000, script);
        }
        {
            auto scriptData = "03200508b17576a9146f9c2fb66458697aa458fb1d25f402a13d9f774388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11354600000000, script);
        }
        {
            auto scriptData = "03200508b17576a9140f64c9f20b635aa2907727b128963036bde9198188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10049900000000, script);
        }
        {
            auto scriptData = "03200508b17576a9145be6b79eb68d1b091928bb77130f6b1488f3c98388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7439800000000, script);
        }
        {
            auto scriptData = "03200508b17576a9142d474c32febf51a5422a9c633d237a38ad970bea88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6175800000000, script);
        }
        {
            auto scriptData = "03200508b17576a91416e293561b0b7dc8a9a178ea13d65533d527d63288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(12052600000000, script);
        }
        {
            auto scriptData = "03200508b17576a9148c17881774b0a8ca1d53e4123871006dc4f5e68188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10802900000000, script);
        }
        {
            auto scriptData = "03200508b17576a91485454b3871d931c9b6ee2ecb9d8cc11990d043d588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(12696900000000, script);
        }
        {
            auto scriptData = "03200508b17576a914e281530836019ef8eec7b6002e7957d9b268577c88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10732900000000, script);
        }
        {
            auto scriptData = "03200508b17576a9145dd8582a03dbd393fda2152c687b03e4c6d4f11788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5004700000000, script);
        }
        {
            auto scriptData = "03200508b17576a9147bc1c6e283e36c30844d026566d78b789ac7f2f188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(12451100000000, script);
        }
        {
            auto scriptData = "03200508b17576a91456066f9b8571cdd18aebcd9518cc8b645a03940c88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8373700000000, script);
        }
        {
            auto scriptData = "03200508b17576a91424bb4db8645e596a46df22f229428075bc5632d488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5859300000000, script);
        }
        {
            auto scriptData = "03200508b17576a914695fb1221df3538b6e41782f37b0c05303a299bd88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8499500000000, script);
        }
        {
            auto scriptData = "03200508b17576a91488bbd1b54b0cfbc3e7c98898b19e099233bb59cb88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4665000000000, script);
        }
        {
            auto scriptData = "03200508b17576a914d89a1a31f7f5947fb18448f0686e4b2dcb41a55188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(9797200000000, script);
        }
        {
            auto scriptData = "03200508b17576a9142b4cb390febdeb9a44f6a961d3634606a17401b288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8660200000000, script);
        }
        {
            auto scriptData = "03200508b17576a9147da281132d8162a7230d8cc8212547e3d434778d88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7152300000000, script);
        }
        {
            auto scriptData = "03200508b17576a914673b420d95c2118ba42be8e2f877e9a3290e94d588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(9518100000000, script);
        }
        {
            auto scriptData = "03200508b17576a914f1eaec65f685ca156b31c032a1fd1fe94c1ef06388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4377600000000, script);
        }
        {
            auto scriptData = "03200508b17576a914bf34e4d862af58ac86214fda0d88b4b53778283988ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(12252400000000, script);
        }
        {
            auto scriptData = "03200508b17576a9148dc841c44ced9335e2dbe8292bb140a32306ef6788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(14275600000000, script);
        }
        {
            auto scriptData = "03200508b17576a91443bbb347f2d9fa27e0cc07ca6bae9378dcea6b0a88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5566400000000, script);
        }
        {
            auto scriptData = "03200508b17576a914ca55932c04fcb554f37bb4c080d3e0aee135483e88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11469800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914dca934d64e642853013685c6edac272a9126266788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5462400000000, script);
        }
        {
            auto scriptData = "03200508b17576a91460fdd36709588d962113dcdd3e3a8fad88247a6a88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(14770300000000, script);
        }
        {
            auto scriptData = "03200508b17576a914a46a16f0108fbf7d001349b4c338a768f4840b0988ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5525400000000, script);
        }
        {
            auto scriptData = "03200508b17576a914fac179eaf11ec27a5ae905502d2a3e1faa259d7988ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7732300000000, script);
        }
        {
            auto scriptData = "03200508b17576a914775d8fee8d3c342b1d9d3d1140b6488eab00597388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7487700000000, script);
        }
        {
            auto scriptData = "03200508b17576a914a6154ec5762b9cc94fd73dbe2065a141591523ce88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7928800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914635d082c94f8ca92b8d490e9baace2335f7a1a5188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10702200000000, script);
        }
        {
            auto scriptData = "03200508b17576a9148871fd93987d7121c5b68eeb03adec0d25ac4d0588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8207700000000, script);
        }
        {
            auto scriptData = "03200508b17576a914ba058391dd8490f25a857378a81d5f714914d59b88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(3888200000000, script);
        }
        {
            auto scriptData = "03200508b17576a914a21739d04e19fc1ffb3aa830c93da9b6f652582488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8205900000000, script);
        }
        {
            auto scriptData = "03200508b17576a91482566557649f28beff8d7b6570be242d72ab8bda88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7668000000000, script);
        }
        {
            auto scriptData = "03200508b17576a9149cc5ecb51ec0d6a85f9b7e3932f4775d9219feb388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11143600000000, script);
        }
        {
            auto scriptData = "03200508b17576a9145455765e6ffd726914f41390a7495747fea593dc88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(13388200000000, script);
        }
        {
            auto scriptData = "03200508b17576a914c56f0054856b9c3296438f52cfe51a4879ad68ca88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7784900000000, script);
        }
        {
            auto scriptData = "03200508b17576a914883191764942ceee19be14bfb8aa3c21ba61446488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(15825100000000, script);
        }
        {
            auto scriptData = "03200508b17576a914bf776d27cc8927b6a4eab4a5d39c12be8cb0eafa88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(14678500000000, script);
        }
        {
            auto scriptData = "03200508b17576a91442f0479c7e1cbba109dab14e3a80590611b5503088ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7222000000000, script);
        }
        {
            auto scriptData = "03200508b17576a9140451c54534d393e385382754b9d8011f9836989e88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11863500000000, script);
        }
        {
            auto scriptData = "03200508b17576a9140ee699fef6e66d45a78a030070c1d233759202f488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11994400000000, script);
        }
        {
            auto scriptData = "03200508b17576a9143ba0251081d86ea3db142de3c9ffb567fa43cb5f88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(16630600000000, script);
        }
        {
            auto scriptData = "03200508b17576a9141ab5feb499af79a2db226af3c78e343e359745ab88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(3485200000000, script);
        }
        {
            auto scriptData = "03200508b17576a91411f511426cf58ecfa8b13bd551d339fd107e80b988ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6557500000000, script);
        }
        {
            auto scriptData = "03200508b17576a914e4f31f767d0ffaea77b2967e0008951a9459933c88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6945400000000, script);
        }
        {
            auto scriptData = "03200508b17576a9144eb8748eb2c2842a3f9beb316c5b38b6a154ab2488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(9011800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914b25b2d459f8f3258f3e1697617ff4634bd214c1388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7776300000000, script);
        }
        {
            auto scriptData = "03200508b17576a914c835acb1d7a0a73733c0cc8a689cb4f2f665a61b88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10905900000000, script);
        }
        {
            auto scriptData = "03200508b17576a914f167c994e1487bdf8c12145b31349301e2c14cd088ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(15648000000000, script);
        }
        {
            auto scriptData = "03200508b17576a914a3ebb239947bda9f1602272c6fd907331d8196bb88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7489300000000, script);
        }
        {
            auto scriptData = "03200508b17576a91401d979e037a69bcb33f1e905ca0542c0b641b1f988ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4585400000000, script);
        }
        {
            auto scriptData = "03200508b17576a914c6b11b8ad4e94dd57915c2087f8723fa0a255aa588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5402400000000, script);
        }
        {
            auto scriptData = "03200508b17576a9145e88453d8d4e12227b864caf7d7e46744894927b88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(12696700000000, script);
        }
        {
            auto scriptData = "03200508b17576a914ead65234f43e045eeaa8c3a9465073c3fb94504b88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8989700000000, script);
        }
        {
            auto scriptData = "03200508b17576a914b17b862393342e8dfe099554a3cebe8b7e77391d88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11604600000000, script);
        }
        {
            auto scriptData = "03200508b17576a9143e2dd2f927e000746e0ce7fa4f90bd349ff879c688ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10589100000000, script);
        }
        {
            auto scriptData = "03200508b17576a9147bc09e3155bd1eae39891b4000fcd246e3b1d97288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(3058200000000, script);
        }
        {
            auto scriptData = "03200508b17576a9149bd51d7828003dc4030aa56c55b600eaac5eb25188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(17066100000000, script);
        }
        {
            auto scriptData = "03200508b17576a914113ca0bd2d5aebda9766c99df3e0e506fc85b84088ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7572800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914b00bf8e5070719ba85726ff5eb463b79be5ca46a88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4171800000000, script);
        }
        {
            auto scriptData = "03200508b17576a91491d3b731526ae1125527d88676f904f494786b2888ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(3695900000000, script);
        }
        {
            auto scriptData = "03200508b17576a914bb2a368a97320398e0222fcdcb85d8ded60e313388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11390200000000, script);
        }
        {
            auto scriptData = "03200508b17576a91429d96b16c625f65004740cc2d216957842e67b8388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(17324500000000, script);
        }
        {
            auto scriptData = "03200508b17576a9146d66b63c795daf440860a6f8cd93c5748376879288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(3209600000000, script);
        }
        {
            auto scriptData = "03200508b17576a914e668d815551e24fa71983f79f694e11d963cde1988ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6250500000000, script);
        }
        {
            auto scriptData = "03200508b17576a914ab308e126159634699173e37a70e069043f040e588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(12526200000000, script);
        }
        {
            auto scriptData = "03200508b17576a914a80a917d9451fba1856e8188acbfdb329f2fb11788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5509300000000, script);
        }
        {
            auto scriptData = "03200508b17576a914b75bf9a16900cc39e62864c2461e7cf06fab937d88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11186800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914282d75bc8685336ab3c0a982575b631a9af724fd88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11980000000000, script);
        }
        {
            auto scriptData = "03200508b17576a914066c6d72978e792d7fdcdd9231c934343934814c88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10970300000000, script);
        }
        {
            auto scriptData = "03200508b17576a91407b977638a830a6478d5d62693b287ca1bc9defc88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11464300000000, script);
        }
        {
            auto scriptData = "03200508b17576a914ffd80217cefbf02b71faf8af6a0c6cd7d4085e3188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10026200000000, script);
        }
        {
            auto scriptData = "03200508b17576a914974e1a75c56c2de815c33cee63ce2ccfc260447d88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(12592400000000, script);
        }
        {
            auto scriptData = "03200508b17576a914a24f87927a74989aaa79e65f51ae35d13b243de488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7048200000000, script);
        }
        {
            auto scriptData = "03200508b17576a914c3a561008846cf65fadaf6da472fa04f840a666888ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(3386900000000, script);
        }
        {
            auto scriptData = "03200508b17576a914325e0daaef01c65645f27eec1a2aed3a29711ef788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8134500000000, script);
        }
        {
            auto scriptData = "03200508b17576a9149bbd6814dc7278a017b99f9959850e7454a8dab588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(3552400000000, script);
        }
        {
            auto scriptData = "03200508b17576a91430017d05eea5d3aeacccc4933a628fe082b3724a88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5559100000000, script);
        }
        {
            auto scriptData = "03200508b17576a914ee38c655a6c11eb0111245c109081e8f29851ff788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11116200000000, script);
        }
        {
            auto scriptData = "03200508b17576a914d03f696c6e6b587c2ccd52ddb4657896654c6be488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11321900000000, script);
        }
        {
            auto scriptData = "03200508b17576a914f1d02a806050b5c07a215e026f70bcf2cdebedee88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4624400000000, script);
        }
        {
            auto scriptData = "03200508b17576a914894e97c179f52254faaf6cd34191ba88b6bee4a088ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10644100000000, script);
        }
        {
            auto scriptData = "03200508b17576a914b7c6f561bbc6165d98c026d7f3f59860338658a388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5835300000000, script);
        }
        {
            auto scriptData = "03200508b17576a914f83cd559d6a628f94e749f62b4f6a6bd7f04a83488ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(2783600000000, script);
        }
        {
            auto scriptData = "03200508b17576a9142abacf2c4444516043330457f9762879a6339ed588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(2684800000000, script);
        }
        {
            auto scriptData = "03200508b17576a9147ff88561e5337213b85798ff084dea7420c3fd8f88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10136400000000, script);
        }
        {
            auto scriptData = "03200508b17576a9146f37ab59c476c239c721569362fa27b059754dac88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8593400000000, script);
        }
        {
            auto scriptData = "03200508b17576a9141453ac9873fc23b357cf940890e59eda745f548288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(3135500000000, script);
        }
        {
            auto scriptData = "03200508b17576a914db42d49e0608b59b169885295aadb25cb8aa390988ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10384200000000, script);
        }
        {
            auto scriptData = "03200508b17576a9148dbc75671997973ae8713137d2ca2fbf0beb250388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6558700000000, script);
        }
        {
            auto scriptData = "03200508b17576a91454e9458a30bd4abb5b9d32e550e022bd2a61e9f188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(3577000000000, script);
        }
        {
            auto scriptData = "03200508b17576a9145ef99be9ec67cd16b14c5fba74a29002b1096aef88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(13570200000000, script);
        }
        {
            auto scriptData = "03200508b17576a914920b745db66dd15415a6b3bc9a6ed6d638e3a5e588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5260700000000, script);
        }
        {
            auto scriptData = "03200508b17576a914b0f59117881ccf4c33dc435e5cfdc07abad7615a88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(9508400000000, script);
        }
        {
            auto scriptData = "03200508b17576a9148b3a5f9a0315367ff9a2749521956f109fe1578a88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(10325700000000, script);
        }
        {
            auto scriptData = "03200508b17576a914ca8100c8195df0245e90106d000ae865b555b6c988ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5737600000000, script);
        }
        {
            auto scriptData = "03200508b17576a91450e991a6c1fb1a8836aa023a8dbec9615317d5a188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(13346600000000, script);
        }
        {
            auto scriptData = "03200508b17576a914bfa620d085cbd97b9868c7919b7a0ee17a6fe08d88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4289500000000, script);
        }
        {
            auto scriptData = "03200508b17576a91413dd33a931dcf33715dcd24cd31cf3478f780bf788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(9339500000000, script);
        }
        {
            auto scriptData = "03200508b17576a9147590447285f8107aa83a5de926d40b6f501cd03588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7378800000000, script);
        }
        {
            auto scriptData = "03200508b17576a9145c7a94c8450174af393c3376fdf998da4660e5c588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(2822800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914ed3ea7457da54ae4cb4b29eb47d0aa7e3f17216d88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7589500000000, script);
        }
        {
            auto scriptData = "03200508b17576a9149675ab4eabce4c6d36c168db02993395946505ce88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(12486300000000, script);
        }
        {
            auto scriptData = "03200508b17576a914051d539d089d1ac6015723eac7a4e8a69435f6d188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11289900000000, script);
        }
        {
            auto scriptData = "03200508b17576a9149b81e5dce0b40bd9671cb9a32dbcf044d86b550f88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7616200000000, script);
        }
        {
            auto scriptData = "03200508b17576a914ba58e9f4d57dbb3f9e302a6b7cfd640c2df0578188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(8505900000000, script);
        }
        {
            auto scriptData = "03200508b17576a914956f03adecf369ac69411c0bcbee4dabc724649288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11356600000000, script);
        }
        {
            auto scriptData = "03200508b17576a9147bef0797bc42b69da7b6ca53c52ed278316b893e88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(7117900000000, script);
        }
        {
            auto scriptData = "03200508b17576a914fc330bea5c9c98de010d799c1d4574c5339c058e88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(15889600000000, script);
        }
        {
            auto scriptData = "03200508b17576a91447dc274d8160762c743cdd940481656a4b0a7b0788ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(12610000000000, script);
        }
        {
            auto scriptData = "03200508b17576a914fe48ae11836bea799ef2d4b36b3a3c80534388bd88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4356200000000, script);
        }
        {
            auto scriptData = "03200508b17576a914929857dc26c3b3c0c2d2ddd6c378ebf68b5af20c88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(2989800000000, script);
        }
        {
            auto scriptData = "03200508b17576a9143ac39371ce12b4e80781ed5e624fb210be3ce40b88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4499200000000, script);
        }
        {
            auto scriptData = "03200508b17576a91489ee624f355a5965ed16da2f061513cda4c4ca2a88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4271600000000, script);
        }
        {
            auto scriptData = "03200508b17576a914a467c0cab57fee63127cf1da0c35f14839d331d188ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4251600000000, script);
        }
        {
            auto scriptData = "03200508b17576a9140d3e8e597367f27dc7e4c27bec157ab7f625fd9688ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5903300000000, script);
        }
        {
            auto scriptData = "03200508b17576a91465e287da912f1e81a80caa014f4d0082cee7b07388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(2792700000000, script);
        }
        {
            auto scriptData = "03200508b17576a914c10f0702b9617f42e6d291cf8ff50e10e23e672e88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5341300000000, script);
        }
        {
            auto scriptData = "03200508b17576a914c7278869d67ee649708ed2925b50db68aebc398588ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6184300000000, script);
        }
        {
            auto scriptData = "03200508b17576a914115188c9d334ad3ecba8d2bdeb67834e48f36ef388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(3975800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914e29d8534879e6343439bbe8b98c70e7e0c3fb59b88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(11340800000000, script);
        }
        {
            auto scriptData = "03200508b17576a914c50baf22e3f6cb1113f12dfcf8ef13f80781ed1b88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6381200000000, script);
        }
        {
            auto scriptData = "03200508b17576a9147c2bb7fe009a82932685b95406e82f48125cea4388ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4730000000000, script);
        }
        {
            auto scriptData = "03200508b17576a914334b4c07032dd9bd47f7d28097c8780a1f0ac7e288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6869900000000, script);
        }
        {
            auto scriptData = "03200508b17576a91426aae55b0086ef9dc6cac99990e3f69274dfb7fd88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6395300000000, script);
        }
        {
            auto scriptData = "03200508b17576a91419f9e36c8895e4e9db2051dbf2353a823211635888ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5461100000000, script);
        }
        {
            auto scriptData = "03200508b17576a914b065a6c9f7da71c7d0b5f1ec5f40f18956cf55c288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6598300000000, script);
        }
        {
            auto scriptData = "03200508b17576a9145fbc41c6c76574dfcb4c20758cf723efc6a2928c88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6346000000000, script);
        }
        {
            auto scriptData = "03200508b17576a914f493c190a0d9ca6fde6f2d62224368fe3ed6044f88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(6376000000000, script);
        }
        {
            auto scriptData = "03200508b17576a914293e8858ddb08ff4cb13f20367ad32ba71ffba7f88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5184400000000, script);
        }
        {
            auto scriptData = "03200508b17576a914e6df9b3154b82320de4a06a0f169b6466030125f88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(4389800000000, script);
        }
        {
            auto scriptData = "03200508b17576a9144bb1b82269018cca9a4219e05956f6aa5f7c7b1b88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5055100000000, script);
        }
        {
            auto scriptData = "03200508b17576a9144976d68927f9de22416edf2420140d24e1be337288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5563700000000, script);
        }
        {
            auto scriptData = "03200508b17576a91418f3c44120fd589ffca7319795135741e159b45f88ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5778000000000, script);
        }
        {
            auto scriptData = "03200508b17576a914686ac7075244b804f80eeb69725419d88debd6f288ac"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(5493400000000, script);
        }
        {
            auto scriptData = "03400a10b175532102b8c1923e042e33e429f32ea184cdc60ad17b1b03afb095d2deb2ad7cacbf32b5210232b1d1f7a695393db56f12d2a1d79fe6187aacf11bf063e15a0bd18992a9ae752103e920a2964bc1fc3d1d0ec82699ed40ba839df6a586ae37974c38f697f2da9f292102b792a0f567966fe166976af02ac56caec13985fb79cbf8e532f9765c3b911e8954ae"_hex_v_u8;
            CScript script(scriptData.begin(), scriptData.end());
            txCoinBase.vout.emplace_back(657000000000000, script);
        }

        CBlock block = CreateGenesisBlock(
                nTime,
                nNounce,
                nBits,
                1,
                {MakeTransactionRef(std::move(txCoinBase))});
        assert(block.GetHash() == BlockHash());
        assert(block.hashMerkleRoot == MerkleRoot());
        return block;
    }
    const uint256& BlockHash() override
    {
        return hashGenesisBlock;
    }
    const uint256& MerkleRoot() override
    {
        return hashMerkleRoot;
    }
};

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.script_flag_exceptions.emplace( // BIP16 exception
            uint256{"00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"}, SCRIPT_VERIFY_NONE);
        consensus.script_flag_exceptions.emplace( // Taproot exception
            uint256{"0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"}, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS);
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256{"000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8"};
        consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.CSVHeight = 419328; // 000000000000000004a1b34462cb8aeebd5799177f7a29cf28f2d1961716b5b5
        consensus.SegwitHeight = 481824; // 0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893
        consensus.MinBIP9WarningHeight = 483840; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = 1619222400; // April 24th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = 1628640000; // August 11th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 709632; // Approximately November 12th, 2021

        consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000000b1f3b93b65b16d035a82be84"};
        consensus.defaultAssumeValid = uint256{"00000000000000000001b658dd1120e82e66d2790811f89ede9742ada3ed6d77"}; // 886157

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd9;
        nDefaultPort = 8333;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 720;
        m_assumed_chain_state_size = 14;

        genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"});
        assert(genesis.hashMerkleRoot == uint256{"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"});

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        vSeeds.emplace_back("seed.bitcoin.sipa.be."); // Pieter Wuille, only supports x1, x5, x9, and xd
        vSeeds.emplace_back("dnsseed.bluematt.me."); // Matt Corallo, only supports x9
        vSeeds.emplace_back("dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us."); // Luke Dashjr
        vSeeds.emplace_back("seed.bitcoin.jonasschnelli.ch."); // Jonas Schnelli, only supports x1, x5, x9, and xd
        vSeeds.emplace_back("seed.btc.petertodd.net."); // Peter Todd, only supports x1, x5, x9, and xd
        vSeeds.emplace_back("seed.bitcoin.sprovoost.nl."); // Sjors Provoost
        vSeeds.emplace_back("dnsseed.emzy.de."); // Stephan Oeste
        vSeeds.emplace_back("seed.bitcoin.wiz.biz."); // Jason Maurice
        vSeeds.emplace_back("seed.mainnet.achownodes.xyz."); // Ava Chow, only supports x1, x5, x9, x49, x809, x849, xd, x400, x404, x408, x448, xc08, xc48, x40c

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                { 11111, uint256{"0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"}},
                { 33333, uint256{"000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6"}},
                { 74000, uint256{"0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20"}},
                {105000, uint256{"00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97"}},
                {134444, uint256{"00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe"}},
                {168000, uint256{"000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763"}},
                {193000, uint256{"000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317"}},
                {210000, uint256{"000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e"}},
                {216116, uint256{"00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e"}},
                {225430, uint256{"00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932"}},
                {250000, uint256{"000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214"}},
                {279000, uint256{"0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40"}},
                {295000, uint256{"00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983"}},
            }
        };

        m_assumeutxo_data = {
            {
                .height = 840'000,
                .hash_serialized = AssumeutxoHash{uint256{"a2a5521b1b5ab65f67818e5e8eccabb7171a517f9e2382208f77687310768f96"}},
                .m_chain_tx_count = 991032194,
                .blockhash = consteval_ctor(uint256{"0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"}),
            },
            {
                .height = 880'000,
                .hash_serialized = AssumeutxoHash{uint256{"dbd190983eaf433ef7c15f78a278ae42c00ef52e0fd2a54953782175fbadcea9"}},
                .m_chain_tx_count = 1145604538,
                .blockhash = consteval_ctor(uint256{"000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880"}),
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 00000000000000000001b658dd1120e82e66d2790811f89ede9742ada3ed6d77
            .nTime    = 1741017141,
            .tx_count = 1161875261,
            .dTxRate  = 4.620728156243148,
        };

        PatchConsensusParams();
        // PatchConsensusParams2();
    }

protected:
    void PatchConsensusParams()
    {
        consensus.nSubsidyHalvingInterval = 2100000;
        consensus.BIP34Height = 1;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;        // miner_tests/CreateNewBlock_validity
        consensus.SegwitHeight = 0;
        consensus.powLimit = uint256{"0000307fffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = 60;
        consensus.fScryptPow = false;
        consensus.fScryptPow = true;
        consensus.nRuleChangeActivationThreshold = 18150; // 90% of 20160
        consensus.nMinerConfirmationWindow = 20160;  // 14 days
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay
        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};
        consensus.nStakeBurnRatio = 9000;
        pchMessageStart[0] = 0x3d;
        pchMessageStart[1] = 0x37;
        pchMessageStart[2] = 0x50;
        pchMessageStart[3] = 0x49;
        m_assumed_blockchain_size = 11;
        m_assumed_chain_state_size = 1;

        CMainNetGenesisBlock genesisBlockMaker;
        genesis = genesisBlockMaker.Create();
        consensus.hashGenesisBlock = genesisBlockMaker.BlockHash();

        assert(consensus.hashGenesisBlock == genesisBlockMaker.BlockHash());
        assert(genesis.hashMerkleRoot == genesisBlockMaker.MerkleRoot());

        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,68);  // P2PKH, start with U     // 0x44
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,130);  // P2SH, start with u    // 0x82
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,196);  // start with 7   // 0xc4    // too many testcase errors
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x4a, 0x52, 0x62}; // upub
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x4a, 0x4e, 0x28}; // uprv
        bech32_hrp = "uto";

        vFixedSeeds.clear();

        // checkpointData = {
        //     {
        //         {0, uint256{"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"}},
        //         // { 11111, uint256{"0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d"}},
        //     }
        // };
        //
        checkpointData = {
            {
                {0, genesisBlockMaker.BlockHash()},
            }
        };
        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 0000000000003ed4f08dbdf6f7d6b271a6bcffce25675cb40aa9fa43179a89f3
            .nTime    = genesis.nTime,
            .tx_count = 1,
            .dTxRate  = 0,
        };
    }

    void PatchConsensusParams2()
    {
        consensus.nSubsidyHalvingInterval = 2100000;
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.powLimit = uint256{"0000307fffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = 60;
        consensus.fScryptPow = true;
        consensus.nRuleChangeActivationThreshold = 18150; // 90% of 20160
        consensus.nMinerConfirmationWindow = 20160;  // 14 days
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay
        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};
        consensus.nStakeBurnRatio = 9000;
        pchMessageStart[0] = 0x3d;
        pchMessageStart[1] = 0x37;
        pchMessageStart[2] = 0x50;
        pchMessageStart[3] = 0x49;
        m_assumed_blockchain_size = 11;
        m_assumed_chain_state_size = 1;

        CMainNetGenesisBlock genesisBlockMaker;
        genesis = genesisBlockMaker.Create();
        consensus.hashGenesisBlock = genesisBlockMaker.BlockHash();

        assert(consensus.hashGenesisBlock == genesisBlockMaker.BlockHash());
        assert(genesis.hashMerkleRoot == genesisBlockMaker.MerkleRoot());

        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,123);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,108);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,141);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xb2, 0x1e};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xad, 0xe4};

        bech32_hrp = "uto";

        vFixedSeeds.clear();

        checkpointData = {
            {
                {0, genesisBlockMaker.BlockHash()},
            }
        };
        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 0000000000003ed4f08dbdf6f7d6b271a6bcffce25675cb40aa9fa43179a89f3
            .nTime    = 0,
            .tx_count = 0,
            .dTxRate  = 0,
        };
    }
};

/**
 * Testnet (v3): public test network which is reset from time to time.
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        m_chain_type = ChainType::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.script_flag_exceptions.emplace( // BIP16 exception
            uint256{"00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"}, SCRIPT_VERIFY_NONE);
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256{"0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8"};
        consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.CSVHeight = 770112; // 00000000025e930139bac5c6c31a403776da130831ab85be56578f3fa75369bb
        consensus.SegwitHeight = 834624; // 00000000002b980fcd729daaa248fd9316a5200e9b367f4ff2c42453e84201ca
        consensus.MinBIP9WarningHeight = 836640; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = 1619222400; // April 24th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = 1628640000; // August 11th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000000000015f5e0c9f13455b0eb17"};
        consensus.defaultAssumeValid = uint256{"00000000000003fc7967410ba2d0a8a8d50daedc318d43e8baf1a9782c236a57"}; // 3974606

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 200;
        m_assumed_chain_state_size = 19;

        genesis = CreateGenesisBlock(1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"});
        assert(genesis.hashMerkleRoot == uint256{"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"});

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-seed.bitcoin.jonasschnelli.ch.");
        vSeeds.emplace_back("seed.tbtc.petertodd.net.");
        vSeeds.emplace_back("seed.testnet.bitcoin.sprovoost.nl.");
        vSeeds.emplace_back("testnet-seed.bluematt.me."); // Just a static list of stable node(s), only supports x9
        vSeeds.emplace_back("seed.testnet.achownodes.xyz."); // Ava Chow, only supports x1, x5, x9, x49, x809, x849, xd, x400, x404, x408, x448, xc08, xc48, x40c

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_test), std::end(chainparams_seed_test));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {546, uint256{"000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70"}},
            }
        };

        m_assumeutxo_data = {
            {
                .height = 2'500'000,
                .hash_serialized = AssumeutxoHash{uint256{"f841584909f68e47897952345234e37fcd9128cd818f41ee6c3ca68db8071be7"}},
                .m_chain_tx_count = 66484552,
                .blockhash = consteval_ctor(uint256{"0000000000000093bcb68c03a9a168ae252572d348a2eaeba2cdf9231d73206f"}),
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 00000000000003fc7967410ba2d0a8a8d50daedc318d43e8baf1a9782c236a57
            .nTime    = 1741042082,
            .tx_count = 475477615,
            .dTxRate  = 17.15933950357594,
        };

        PatchConsensusParams();
    }

protected:
    void PatchConsensusParams()
    {
        consensus.fScryptPow = false;
        consensus.nStakeBurnRatio = 9000;
    }
};

/**
 * Testnet (v4): public test network which is reset from time to time.
 */
class CTestNet4Params : public CChainParams {
public:
    CTestNet4Params() {
        m_chain_type = ChainType::TESTNET4;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000000000001d6dce8651b6094e4c1"};
        consensus.defaultAssumeValid = uint256{"0000000000003ed4f08dbdf6f7d6b271a6bcffce25675cb40aa9fa43179a89f3"}; // 72600

        pchMessageStart[0] = 0x1c;
        pchMessageStart[1] = 0x16;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x28;
        nDefaultPort = 48333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 11;
        m_assumed_chain_state_size = 1;

        const char* testnet4_genesis_msg = "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e";
        const CScript testnet4_genesis_script = CScript() << "000000000000000000000000000000000000000000000000000000000000000000"_hex << OP_CHECKSIG;
        genesis = CreateGenesisBlock(testnet4_genesis_msg,
                testnet4_genesis_script,
                1714777860,
                393743547,
                0x1d00ffff,
                1,
                50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"});
        assert(genesis.hashMerkleRoot == uint256{"7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"});

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("seed.testnet4.bitcoin.sprovoost.nl."); // Sjors Provoost
        vSeeds.emplace_back("seed.testnet4.wiz.biz."); // Jason Maurice

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_testnet4), std::end(chainparams_seed_testnet4));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {},
            }
        };

        m_assumeutxo_data = {
            {}
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 0000000000003ed4f08dbdf6f7d6b271a6bcffce25675cb40aa9fa43179a89f3
            .nTime    = 1741070246,
            .tx_count = 7653966,
            .dTxRate  = 1.239174414591965,
        };
        PatchConsensusParams();
    }
protected:
    void PatchConsensusParams()
    {
        consensus.nSubsidyHalvingInterval = 2100000;
        consensus.BIP34Height = 0;
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.CSVHeight = 0;
        consensus.SegwitHeight = 0;
        consensus.powLimit = uint256{"0000307fffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = 60;
        consensus.fScryptPow = true;
        consensus.nRuleChangeActivationThreshold = 15120; // 75% for testchains
        consensus.nMinerConfirmationWindow = 20160;  // 14 days
        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};
        consensus.nStakeBurnRatio = 9000;
        pchMessageStart[0] = 0x2d;
        pchMessageStart[1] = 0x27;
        pchMessageStart[2] = 0x40;
        pchMessageStart[3] = 0x39;

        CTestNet4GenesisBlock genesisBlockMaker;
        genesis = genesisBlockMaker.Create();
        consensus.hashGenesisBlock = genesisBlockMaker.BlockHash();

        assert(consensus.hashGenesisBlock == genesisBlockMaker.BlockHash());
        assert(genesis.hashMerkleRoot == genesisBlockMaker.MerkleRoot());

        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,222);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,207);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,240);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x15, 0x46, 0x98, 0xD0};
        base58Prefixes[EXT_SECRET_KEY] = {0x15, 0x46, 0x94, 0xA5};

        bech32_hrp = "tu";

        checkpointData = {
            {
                {0, genesisBlockMaker.BlockHash()},
            }
        };
        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 0000000000003ed4f08dbdf6f7d6b271a6bcffce25675cb40aa9fa43179a89f3
            .nTime    = 0,
            .tx_count = 0,
            .dTxRate  = 0,
        };
    }
};

/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vFixedSeeds.clear();
        vSeeds.clear();

        if (!options.challenge) {
            bin = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"_hex_v_u8;
            vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_signet), std::end(chainparams_seed_signet));
            vSeeds.emplace_back("seed.signet.bitcoin.sprovoost.nl.");
            vSeeds.emplace_back("seed.signet.achownodes.xyz."); // Ava Chow, only supports x1, x5, x9, x49, x809, x849, xd, x400, x404, x408, x448, xc08, xc48, x40c

            consensus.nMinimumChainWork = uint256{"000000000000000000000000000000000000000000000000000002b517f3d1a1"};
            consensus.defaultAssumeValid = uint256{"000000895a110f46e59eb82bbc5bfb67fa314656009c295509c21b4999f5180a"}; // 237722
            m_assumed_blockchain_size = 9;
            m_assumed_chain_state_size = 1;
            chainTxData = ChainTxData{
                // Data from RPC: getchaintxstats 4096 000000895a110f46e59eb82bbc5bfb67fa314656009c295509c21b4999f5180a
                .nTime    = 1741019645,
                .tx_count = 16540736,
                .dTxRate  = 1.064918879911595,
            };
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"00000377ae000000000000000000000000000000000000000000000000000000"};
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 38333;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1598918400, 52613770, 0x1e0377ae, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"});
        assert(genesis.hashMerkleRoot == uint256{"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"});

        m_assumeutxo_data = {
            {
                .height = 160'000,
                .hash_serialized = AssumeutxoHash{uint256{"fe0a44309b74d6b5883d246cb419c6221bcccf0b308c9b59b7d70783dbdf928a"}},
                .m_chain_tx_count = 2289496,
                .blockhash = consteval_ctor(uint256{"0000003ca3c99aff040f2563c2ad8f8ec88bd0fd6b8f0895cfaf1ef90353a62c"}),
            }
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        PatchConsensusParams();
    }
protected:
    void PatchConsensusParams()
    {
        consensus.fScryptPow = false;
        consensus.nStakeBurnRatio = 9000;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 0; // Always active unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = opts.enforce_bip94;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"});
        assert(genesis.hashMerkleRoot == uint256{"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"});

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256{"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"}},
            }
        };

        m_assumeutxo_data = {
            {   // For use by unit tests
                .height = 110,
                .hash_serialized = AssumeutxoHash{uint256{"6657b736d4fe4db0cbc796789e812d5dba7f5c143764b1b6905612f1830609d1"}},
                .m_chain_tx_count = 111,
                .blockhash = consteval_ctor(uint256{"696e92821f65549c7ee134edceeeeaaa4105647a3c4fd9f298c0aec0ab50425c"}),
            },
            {
                // For use by fuzz target src/test/fuzz/utxo_snapshot.cpp
                .height = 200,
                .hash_serialized = AssumeutxoHash{uint256{"4f34d431c3e482f6b0d67b64609ece3964dc8d7976d02ac68dd7c9c1421738f2"}},
                .m_chain_tx_count = 201,
                .blockhash = consteval_ctor(uint256{"5e93653318f294fb5aa339d00bbf8cf1c3515488ad99412c37608b139ea63b27"}),
            },
            {
                // For use by test/functional/feature_assumeutxo.py
                .height = 299,
                .hash_serialized = AssumeutxoHash{uint256{"a4bf3407ccb2cc0145c49ebba8fa91199f8a3903daf0883875941497d2493c27"}},
                .m_chain_tx_count = 334,
                .blockhash = consteval_ctor(uint256{"3bb7ce5eba0be48939b7a521ac1ba9316afee2c7bada3a0cca24188e6d7d96c0"}),
            },
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";

        PatchConsensusParams();
    }
protected:
    void PatchConsensusParams()
    {
        consensus.fScryptPow = true;
        consensus.nStakeBurnRatio = 9000;

        std::unique_ptr<CGenesisBlock> genesisBlockMaker;
        if (consensus.fScryptPow) {
            genesisBlockMaker = std::make_unique<CRegTestGenesisBlockScrypt>();
        } else {
            genesisBlockMaker = std::make_unique<CRegTestGenesisBlock>();
        }

        genesis = genesisBlockMaker->Create();

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == genesisBlockMaker->BlockHash());
        assert(genesis.hashMerkleRoot == genesisBlockMaker->MerkleRoot());

        checkpointData = {
            {
                {0, genesisBlockMaker->BlockHash()},
            }
        };

        if ( consensus.fScryptPow ) {
            m_assumeutxo_data = {
                {   // For use by unit tests
                    .height = 110,
                    // .hash_serialized = AssumeutxoHash{uint256{"6657b736d4fe4db0cbc796789e812d5dba7f5c143764b1b6905612f1830609d1"}}, // other ok
                    .hash_serialized = AssumeutxoHash{uint256{"4f5b670d17bf4f9b211ac3a9f0ad424721c338cb1451b1b1c0ab968e87bedfbd"}}, // other ok
                    .m_chain_tx_count = 111,
                    .blockhash = consteval_ctor(uint256{"0c2db269233208c7bd6f2537d80207ff3042c84e1d5a4be8661bf8a5bae07af5"}),
                    // .blockhash = consteval_ctor(uint256{"ca177c9f3eed98474469fa199e2816c6d9a4802ad18a973fc96180e4d0580558"}),
                },
                {
                    // For use by fuzz target src/test/fuzz/utxo_snapshot.cpp
                    .height = 200,
                    .hash_serialized = AssumeutxoHash{uint256{"4f34d431c3e482f6b0d67b64609ece3964dc8d7976d02ac68dd7c9c1421738f2"}},
                    .m_chain_tx_count = 201,
                    .blockhash = consteval_ctor(uint256{"604c76ba4bca6db7333d364f91d478833fde9f48c2c138a13eaff6a8289a0263"}),
                },
                {
                    // For use by test/functional/feature_assumeutxo.py
                    .height = 299,
                    // .hash_serialized = AssumeutxoHash{uint256{"a4bf3407ccb2cc0145c49ebba8fa91199f8a3903daf0883875941497d2493c27"}},
                    .hash_serialized = AssumeutxoHash{uint256{"616172cef986be0dda85ff4a4b9dac1322d514ea1eeaca2b5541377ca26521bd"}},
                    .m_chain_tx_count = 334,
                    .blockhash = consteval_ctor(uint256{"1e1437d69143ee7317f438afa29479e947694a77de48cd95e0f75603a4cb9d1c"}),
                },
            };
        }
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet()
{
    return std::make_unique<const CTestNetParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet4()
{
    return std::make_unique<const CTestNet4Params>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet_msg = CChainParams::TestNet()->MessageStart();
    const auto testnet4_msg = CChainParams::TestNet4()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();
    const auto signet_msg = CChainParams::SigNet({})->MessageStart();

    if (std::ranges::equal(message, mainnet_msg)) {
        return ChainType::MAIN;
    } else if (std::ranges::equal(message, testnet_msg)) {
        return ChainType::TESTNET;
    } else if (std::ranges::equal(message, testnet4_msg)) {
        return ChainType::TESTNET4;
    } else if (std::ranges::equal(message, regtest_msg)) {
        return ChainType::REGTEST;
    } else if (std::ranges::equal(message, signet_msg)) {
        return ChainType::SIGNET;
    }
    return std::nullopt;
}
