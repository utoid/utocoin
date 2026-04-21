// Copyright (c) 2025 The Utocoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utocoin/stake_promise.h"
#include "utocoin/test/utocoin_test_fixture.h"
#include <boost/test/unit_test.hpp>
#include <utility>
#include <script/signingprovider.h>
#include "script/interpreter.h"
#include "util/strencodings.h"

#include <policy/policy.h>
#include <script/sign.h>

using namespace std;
using namespace util::hex_literals;

namespace utocoin::test {


BOOST_FIXTURE_TEST_SUITE(promise_tests, UtocoinTestingSetup)

BOOST_AUTO_TEST_CASE(stake_promise)
{
    CStakePromise empty;
    BOOST_CHECK(empty.IsNull());

    CStakePromise notEmpty;
    notEmpty.m_pubkey = valtype(33, 1);
    BOOST_CHECK(!notEmpty.IsNull());
    BOOST_CHECK(notEmpty.AnyNull());
    BOOST_CHECK(notEmpty.AnyNullWithoutSignature());

    CStakePromise noSignature(
        COutPoint(Txid::FromUint256(uint256(8)), 3), // utxo
        valtype(20, 2),                              // toAddr
        COutPoint(Txid::FromUint256(uint256(6)), 6)  // stakeUtxo
    );
    BOOST_CHECK(!noSignature.IsNull());
    BOOST_CHECK(noSignature.AnyNull());
    BOOST_CHECK(!noSignature.AnyNullWithoutSignature());

    CStakePromise withSignature(
        COutPoint(Txid::FromUint256(uint256(8)), 3), // utxo
        valtype(20, 2),                              // toAddr
        COutPoint(Txid::FromUint256(uint256(6)), 6), // stakeUtxo
        valtype(33, 3),                              // pubKey
        valtype(72, 4)                               // signature
    );
    BOOST_CHECK(!withSignature.IsNull());
    BOOST_CHECK(!withSignature.AnyNull());
    BOOST_CHECK(!withSignature.AnyNullWithoutSignature());

    // test could be added to CScript
    CScript s;
    valtype v(withSignature);
    s << v;
}

BOOST_AUTO_TEST_CASE(serialize)
{
    valtype vchOutput;
    for (auto&& cs : vector<CStakePromise>{
             CStakePromise(), // IsNull()

             CStakePromise(COutPoint(Txid::FromUint256(uint256(8)), 7636421), valtype(), COutPoint()),                                // !IsNull(), AnyNullWithoutSignature(), AnyNull()
             CStakePromise(COutPoint(Txid::FromUint256(uint256(8)), 3), valtype(20, 2), COutPoint(Txid::FromUint256(uint256(6)), 6)), // !IsNull(), !AnyNullWithoutSignature(), AnyNull()
         }) {
        BOOST_CHECK_THROW(cs.Serialize(vchOutput), std::runtime_error);
    }
    CStakePromise promise(
        COutPoint(Txid::FromUint256(uint256(8)), 7636421), // utxo
        valtype(20, 2),                                    // toAddr
        COutPoint(Txid::FromUint256(uint256(6)), 6),       // stakeUtxo
        valtype(33, 3),                                    // pubKey
        valtype(72, 4)                                     // signature
    );

    promise.Serialize(vchOutput);
    auto data = vector<unsigned char>(promise);
    BOOST_CHECK(data == vchOutput);

    CStakePromise other;
    other.Deserialize({});
    BOOST_CHECK(other.IsNull());
    other.Deserialize(data);
    BOOST_CHECK(!other.IsNull());
    BOOST_CHECK(!other.AnyNull());
    BOOST_CHECK(!other.AnyNullWithoutSignature());

    BOOST_CHECK(promise == other);

    uint256 hash1;
    uint256 hash2;
    hash1 = promise.Hash();
    hash2 = other.Hash();
    BOOST_CHECK(hash1 == hash2);
}

BOOST_AUTO_TEST_CASE(promise_sign)
{
    CKey secret;
    secret.MakeNewKey(true);

    CStakePromise promise(
        COutPoint(Txid::FromUint256(uint256(8)), 7636421), // utxo
        valtype(20, 2),                                    // toAddr
        COutPoint(Txid::FromUint256(uint256(6)), 6)        // stakeUtxo
    );

    promise.Sign(secret);
    BOOST_CHECK(promise.Verify<CPubKey>());

    promise.m_signature[0] = promise.m_signature[0] + 1;
    BOOST_CHECK(!promise.Verify<CPubKey>());

    valtype output;
    promise.Serialize(output);

    CStakePromise other;
    other.Deserialize(output);
    BOOST_CHECK(promise == other);
}

BOOST_AUTO_TEST_CASE(test_taproot)
{
    CKey key;
    key.MakeNewKey(true);
    BOOST_CHECK(key.IsValid());
    CPubKey pubkey = key.GetPubKey();

    // construct P2PK script
    CScript scriptPK;
    scriptPK << ToByteVector(XOnlyPubKey{pubkey}) << OP_CHECKSIG;

    TaprootBuilder builder;
    builder.Add(0, scriptPK, TAPROOT_LEAF_TAPSCRIPT);
    BOOST_CHECK(builder.IsComplete());
    builder.Finalize(XOnlyPubKey::NUMS_H);
    WitnessV1Taproot taproot = builder.GetOutput();
    TaprootSpendData spend_data =  builder.GetSpendData();

    CScript p2tr_script_pub_key;
    p2tr_script_pub_key << OP_1 << ToByteVector(taproot);

    auto p2tr_script_pub_key_gen = GetScriptForDestination(taproot);
    BOOST_REQUIRE(p2tr_script_pub_key == p2tr_script_pub_key_gen);

    auto it = spend_data.scripts.find(std::make_pair(ToByteVector(scriptPK), TAPROOT_LEAF_TAPSCRIPT));
    BOOST_REQUIRE(it != spend_data.scripts.end());
    auto control_block = it->second;

    CScript scriptOutput;
    scriptOutput << OP_RETURN << ToByteVector("0619873211"_hex_u8);

    Txid prevTx = Txid::FromUint256(uint256::ONE);
    CMutableTransaction spending_tx;
    spending_tx.vin.push_back(CTxIn(COutPoint(prevTx, 0)));
    spending_tx.vout.push_back(CTxOut(80000, scriptOutput));
    CTransaction spending_tx_const(spending_tx);

    PrecomputedTransactionData txdata;
    txdata.Init(spending_tx_const, std::vector<CTxOut>{spending_tx_const.vout}, true);
    // try use ProduceSignature
    {
        FlatSigningProvider provider;
        provider.keys.insert(std::make_pair(pubkey.GetID(), key));
        provider.tr_trees.insert(std::make_pair(taproot, builder));

        auto signer = MutableTransactionSignatureCreator(spending_tx, 0, 80000, &txdata, SIGHASH_ALL);

        SignatureData sigdata;
        BOOST_REQUIRE(ProduceSignature(provider, signer, p2tr_script_pub_key, sigdata));

        UpdateInput(spending_tx.vin[0], sigdata);
        auto tx = MakeTransactionRef(spending_tx);
        TransactionSignatureChecker checker(tx.get(), 0, 80000, txdata, MissingDataBehavior::ASSERT_FAIL);

        ScriptError serr;
        bool result = VerifyScript(CScript(), p2tr_script_pub_key, &sigdata.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serr);
        BOOST_CHECK(result);
    }

    // try unlock manual
    {
        auto it = spend_data.scripts.find(std::make_pair(ToByteVector(scriptPK), TAPROOT_LEAF_TAPSCRIPT));
        BOOST_REQUIRE(it != spend_data.scripts.end());
        auto [script_version, control_blocks] = *it;
        auto [script, leaf_version] = script_version;
        uint256 leaf_hash = ComputeTapleafHash(TAPROOT_LEAF_TAPSCRIPT, script);
        std::vector<unsigned char> sig;

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
        uint256 hash;
        auto nHashType = SIGHASH_ALL;
        BOOST_REQUIRE(SignatureHashSchnorr(hash, execdata, spending_tx_const, 0, nHashType, SigVersion::TAPSCRIPT, txdata, MissingDataBehavior::FAIL));

        sig.resize(64);
        uint256* merkle_root = nullptr;
        // Use uint256{} as aux_rnd for now.
        BOOST_REQUIRE(key.SignSchnorr(hash, sig, merkle_root, {}));
        if (nHashType) sig.push_back(nHashType);

        // make a wrong sig
        // sig[8] ^= 1;
        std::vector<std::vector<unsigned char>> result_stack;
        result_stack.push_back(sig);                                     // Push signature
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

} // namespace utocoin
