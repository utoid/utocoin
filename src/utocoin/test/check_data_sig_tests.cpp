// Copyright (c) 2025 The Utocoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utocoin/stake_promise.h"
#include "utocoin/test/utocoin_test_fixture.h"
#include <boost/test/unit_test.hpp>
#include <chrono>
#include <policy/policy.h>
#include <random>
#include <scheduler.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <util/strencodings.h>
#include <utility>
#include <utocoin/script/functional_checker.h>

using namespace std;
using namespace util::hex_literals;

namespace utocoin::test {

BOOST_FIXTURE_TEST_SUITE(check_datsig_tests, UtocoinTestingSetup)

BOOST_AUTO_TEST_CASE(test_hash_blender)
{
    uint256 originHash = uint256::ZERO;
    std::vector<unsigned char> data = random_vector();
    uint256 blended_hash = Hash(Hash(data), originHash);

    uint256 expected_hash = originHash;

    script::CFunctionalChecker checker(BaseSignatureChecker{});

    checker.m_fnCheckECDSASignature = [&](const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) -> bool {
        uint256 hash = originHash;
        checker.SighashBlender(hash);
        BOOST_CHECK(hash == expected_hash);
        return true;
    };
    checker.m_fnCheckSchnorrSignature = [&](Span<const unsigned char> sig, Span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror) -> bool {
        uint256 hash = originHash;
        checker.SighashBlender(hash);
        BOOST_CHECK(hash == expected_hash);
        return true;
    };
    checker.m_fnSighashBlender = [&](uint256& hash) {
        return checker.BaseSignatureChecker::SighashBlender(hash);
    };

    ScriptExecutionData exec_data;
    checker.CheckECDSASignature(std::vector<unsigned char>(), std::vector<unsigned char>(), CScript(), SigVersion::BASE);
    checker.CheckSchnorrSignature(std::vector<unsigned char>(), std::vector<unsigned char>(), SigVersion::TAPROOT, exec_data, nullptr);

    expected_hash = blended_hash;
    checker.WithSighashBlender(data, [&]() -> bool {
        return checker.CheckECDSASignature(std::vector<unsigned char>(), std::vector<unsigned char>(), CScript(), SigVersion::BASE);
    });
    checker.WithSighashBlender(data, [&]() -> bool {
        return checker.CheckSchnorrSignature(std::vector<unsigned char>(), std::vector<unsigned char>(), SigVersion::TAPROOT, exec_data, nullptr);
    });

    expected_hash = originHash;
    checker.CheckECDSASignature(std::vector<unsigned char>(), std::vector<unsigned char>(), CScript(), SigVersion::BASE);
    checker.CheckSchnorrSignature(std::vector<unsigned char>(), std::vector<unsigned char>(), SigVersion::TAPROOT, exec_data, nullptr);
}

BOOST_AUTO_TEST_CASE(test_pay2tr)
{
    CKey key0, key1, key2;
    key0.MakeNewKey(true);
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);
    BOOST_CHECK(key0.IsValid() && key1.IsValid() && key2.IsValid());
    CPubKey pubkey0 = key0.GetPubKey(); // internal pubkey
    CPubKey pubkey1 = key1.GetPubKey(); // payer pubkey
    CPubKey pubkey2 = key2.GetPubKey(); // payee pubkey

    // construct P2PK script
    CScript scriptPK;
    scriptPK << ToByteVector(XOnlyPubKey{pubkey1}) << OP_CHECKDATSIGVERIFY << OP_CHECKSIG;

    TaprootBuilder builder;
    builder.Add(0, scriptPK, TAPROOT_LEAF_TAPSCRIPT);
    BOOST_CHECK(builder.IsComplete());
    builder.Finalize(XOnlyPubKey{pubkey0});
    WitnessV1Taproot taproot = builder.GetOutput();
    TaprootSpendData spend_data = builder.GetSpendData();

    // CScript p2tr_script_pub_key;
    // p2tr_script_pub_key << OP_1 << ToByteVector(taproot);
    CScript p2tr_script_pub_key = GetScriptForDestination(taproot);

    CScript scriptOutput;
    scriptOutput << OP_RETURN << ToByteVector("0619873211"_hex_u8);

    Txid prevTx = Txid::FromUint256(uint256::ONE);
    CMutableTransaction spending_tx;
    spending_tx.vin.push_back(CTxIn(COutPoint(prevTx, 0)));
    spending_tx.vout.push_back(CTxOut(80000, scriptOutput));
    CTransaction spending_tx_const(spending_tx);

    PrecomputedTransactionData txdata;
    txdata.Init(spending_tx_const, std::vector<CTxOut>{spending_tx_const.vout}, true);

    // try key path unlock, with builder
    {
        FlatSigningProvider provider;
        provider.keys.insert(std::make_pair(pubkey0.GetID(), key0));
        provider.tr_trees.insert(std::make_pair(taproot, builder));

        auto signer = MutableTransactionSignatureCreator(spending_tx, 0, 80000, &txdata, SIGHASH_ALL);
        std::vector<unsigned char> sig;

        SignatureData sigdata;
        BOOST_REQUIRE(ProduceSignature(provider, signer, p2tr_script_pub_key, sigdata));

        UpdateInput(spending_tx.vin[0], sigdata);

        auto tx = MakeTransactionRef(spending_tx);

        TransactionSignatureChecker checker(tx.get(), 0, 80000, txdata, MissingDataBehavior::ASSERT_FAIL);
        ScriptError serr;
        bool result = VerifyScript(CScript(), p2tr_script_pub_key, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serr);
        BOOST_CHECK(result);
    }

    // try script path unlock
    {
        auto it = spend_data.scripts.find(std::make_pair(ToByteVector(scriptPK), TAPROOT_LEAF_TAPSCRIPT));
        BOOST_REQUIRE(it != spend_data.scripts.end());
        auto [script_version, control_blocks] = *it;
        auto [script, leaf_version] = script_version;
        uint256 leaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, script);

        ScriptExecutionData execdata;
        execdata.m_annex_init = true;
        execdata.m_annex_present = false; // Only support annex-less signing for now.
        // if (sigversion == SigVersion::TAPSCRIPT) {
        execdata.m_codeseparator_pos_init = true;
        execdata.m_codeseparator_pos = 0xFFFFFFFF; // Only support non-OP_CODESEPARATOR BIP342 signing for now.
        // if (!leaf_hash) return false; // BIP342 signing needs leaf hash.
        execdata.m_tapleaf_hash_init = true;
        execdata.m_tapleaf_hash = leaf_hash;
        // }
        uint256 txhash;
        auto nHashType = SIGHASH_ALL;
        BOOST_REQUIRE(SignatureHashSchnorr(txhash, execdata, spending_tx_const, 0, nHashType, SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL));

        // This part with be provied as payer witness
        std::vector<unsigned char> sig1;
        sig1.resize(64);
        uint256* merkle_root = nullptr;
        auto data_hash = Hash(XOnlyPubKey{pubkey2});
        auto blend_hash = Hash(data_hash, txhash);

        // Use uint256{} as aux_rnd for now.
        BOOST_REQUIRE(key1.SignSchnorr(blend_hash, sig1, merkle_root, {}));
        if (nHashType) sig1.push_back(nHashType);

        // This part will be provied as payee witness
        std::vector<unsigned char> sig2;
        sig2.resize(64);
        BOOST_REQUIRE(key2.SignSchnorr(txhash, sig2, merkle_root, {}));
        if (nHashType) sig2.push_back(nHashType);

        // make a wrong sig
        // sig1[8] ^= 1;
        // sig2[8] ^= 1;

        std::vector<std::vector<unsigned char>> result_stack;
        result_stack.push_back(sig2);                               // Push signature by key2
        result_stack.push_back(sig1);                               // Push signature by key1
        result_stack.push_back(ToByteVector(XOnlyPubKey{pubkey2})); // Push pubkey2

        result_stack.emplace_back(std::begin(script), std::end(script)); // Push the script
        result_stack.push_back(*control_blocks.begin());                 // Push the smallest control block

        SignatureData sigdata;
        // sigdata.tr_spenddata = spend_data;
        // sigdata.tr_builder = {builder};
        sigdata.scriptWitness.stack = std::move(result_stack);

        UpdateInput(spending_tx.vin[0], sigdata);
        auto tx = MakeTransactionRef(spending_tx);
        TransactionSignatureChecker checker(tx.get(), 0, 80000, txdata, MissingDataBehavior::ASSERT_FAIL);

        ScriptError serr;
        bool result = VerifyScript(CScript(), p2tr_script_pub_key, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serr);
        BOOST_CHECK(result);
    }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace utocoin::test
