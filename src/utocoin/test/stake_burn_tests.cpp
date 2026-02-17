// Copyright (c) 2025 The Utocoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utocoin/test/utocoin_test_fixture.h"

#include "addresstype.h"

#include <any>
#include <boost/test/unit_test.hpp>
#include <boost/variant/variant.hpp>
#include <random>
#include <script/interpreter.h>
#include <script/signingprovider.h>

#include <boost/test/utils/runtime/parameter.hpp>
#include <index/txindex.h>
#include <policy/policy.h>
#include <script/parsing.h>
#include <script/sign.h>
#include <utility>
#include <kernel/chainparams.h>
#include <utocoin/script/signer_pickup_checker.h>
#include <utocoin/script/transaction_getter.h>
#include <utocoin/stake_promise.h>

#include <sstream>

namespace utocoin::test {
using namespace std;

namespace {
uint32_t RandInt(uint32_t nMax)
{
    std::mt19937 engine(std::chrono::system_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<uint32_t> dist(0, nMax - 1);
    return dist(engine);
}

uint256 RandUint256()
{
    uint256 result;
    std::mt19937 engine(std::chrono::system_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<unsigned int> dist(0, 255);
    std::generate(result.begin(), result.end(), [&]() { return static_cast<unsigned char>(dist(engine)); });
    return result;
}

enum class OutputFormat {
    SCRIPT,
    SCRIPT_HASH,
    WITNESS_SCRIPT_HASH,
    TAPROOT
};

constexpr string_view OutputFormatToString(OutputFormat fmt)
{
    switch (fmt) {
    case OutputFormat::SCRIPT: return "SCRIPT";
    case OutputFormat::SCRIPT_HASH: return "SCRIPT_HASH";
    case OutputFormat::WITNESS_SCRIPT_HASH: return "WITNESS_SCRIPT_HASH";
    case OutputFormat::TAPROOT: return "TAPROOT";
    default: return "UNKNOWN";
    }
}

constexpr array<OutputFormat, 4> allFormat = {
    OutputFormat::SCRIPT,
    OutputFormat::SCRIPT_HASH,
    OutputFormat::WITNESS_SCRIPT_HASH,
    OutputFormat::TAPROOT,
};

class DummySign
{
};

using DataElement = std::variant<vector<unsigned char>, CPubKey, uint32_t, opcodetype, DummySign>;

template <uint32_t OutputCount = 5>
class COutputTxBuilder
{
public:
    uint32_t m_nOutput;
    CScript m_scriptPubkey;

    std::optional<XOnlyPubKey> m_pubkeyInternal;
    OutputFormat m_outputFormat;
    TaprootBuilder m_builder;
    CAmount m_nAmount;

    vector<DataElement> m_vecScript;

    COutputTxBuilder()
        : m_nOutput(RandInt(OutputCount)),
          m_outputFormat(OutputFormat::SCRIPT),
          m_nAmount(0)
    {
    }

    uint32_t Output()
    {
        return m_nOutput;
    }

    COutputTxBuilder& WithInternalPubkey(const XOnlyPubKey& pubkeyInternal)
    {
        m_pubkeyInternal = pubkeyInternal;
        return *this;
    }

    COutputTxBuilder& WithOutputFormat(OutputFormat outputFormat)
    {
        m_outputFormat = outputFormat;
        return *this;
    }

    COutputTxBuilder& WithAmount(CAmount nAmount)
    {
        m_nAmount = nAmount;
        return *this;
    }

    COutputTxBuilder& operator<<(const DataElement& elem)
    {
        m_vecScript.push_back(elem);
        return *this;
    }

    CTransactionRef Build(const std::vector<CTxIn>& vin = {})
    {
        CScript script = MakeScriptPubkey();
        CMutableTransaction txNew;

        txNew.vin = vin;
        txNew.vout.resize(OutputCount);
        txNew.vout[m_nOutput] = CTxOut(m_nAmount, script);
        return MakeTransactionRef(txNew);
    }

    CScript MakeScriptPubkey()
    {
        for (const auto& elem : m_vecScript) {
            std::visit(
                [this](auto&& arg) {
                    using T = std::decay_t<decltype(arg)>;
                    if constexpr (std::is_same_v<T, CPubKey>) {
                        if (m_outputFormat == OutputFormat::TAPROOT) {
                            this->m_scriptPubkey << ToByteVector(XOnlyPubKey{arg});
                        } else {
                            this->m_scriptPubkey << ToByteVector(arg);
                        }
                    } else if constexpr (std::is_same_v<T, uint32_t>) {
                        this->m_scriptPubkey << arg;
                    } else if constexpr (std::is_same_v<T, DummySign>) {
                        abort();
                    } else {
                        this->m_scriptPubkey << arg;
                    }
                },
                elem);
        }

        CScript scriptOutput;
        switch (m_outputFormat) {
        case OutputFormat::SCRIPT:
            scriptOutput = m_scriptPubkey;
            break;

        case OutputFormat::SCRIPT_HASH:
            scriptOutput << OP_HASH160 << ToByteVector(CScriptID(m_scriptPubkey)) << OP_EQUAL;
            break;

        case OutputFormat::WITNESS_SCRIPT_HASH:
            scriptOutput << OP_0 << ToByteVector(WitnessV0ScriptHash(m_scriptPubkey));
            break;

        case OutputFormat::TAPROOT:
            m_builder.Add(1, m_scriptPubkey, TAPROOT_LEAF_TAPSCRIPT);
            m_builder.AddOmitted(1, RandUint256());
            assert(m_pubkeyInternal);
            m_builder.Finalize(*m_pubkeyInternal);

            scriptOutput << OP_1 << ToByteVector(m_builder.GetOutput());

            break;
        default: throw std::runtime_error("invalid output format");
        }
        return scriptOutput;
    }

    COutputTxBuilder& Reset()
    {
        m_scriptPubkey = CScript();
        m_builder = TaprootBuilder();
        return *this;
    }

    void MakeSignatureData(SignatureData& sig, const vector<DataElement>& wit)
    {
        switch (m_outputFormat) {
        case OutputFormat::SCRIPT:
        case OutputFormat::SCRIPT_HASH:
            for (const auto& elem : wit) {
                std::visit(
                    [&sig](auto&& arg) {
                        using T = std::decay_t<decltype(arg)>;
                        if constexpr (std::is_same_v<T, CPubKey>) {
                            sig.scriptSig << ToByteVector(arg);
                        } else if constexpr (std::is_same_v<T, DummySign>) {
                            sig.scriptSig << vector<unsigned char>{};
                        } else if constexpr (std::is_same_v<T, uint32_t>) {
                            sig.scriptSig << arg;
                        } else {
                            sig.scriptSig << arg;
                        }
                    },
                    elem);
            }
            if (m_outputFormat == OutputFormat::SCRIPT_HASH) {
                sig.scriptSig << ToByteVector(m_scriptPubkey);
            }
            break;
        case OutputFormat::WITNESS_SCRIPT_HASH:
        case OutputFormat::TAPROOT:
            for (const auto& elem : wit) {
                sig.scriptWitness.stack.push_back(std::visit(
                    [this](auto&& arg) -> vector<unsigned char> {
                        using T = std::decay_t<decltype(arg)>;
                        if constexpr (std::is_same_v<T, CPubKey>) {
                            if (m_outputFormat == OutputFormat::TAPROOT) {
                                return ToByteVector(XOnlyPubKey{arg});
                            } else {
                                return ToByteVector(arg);
                            }
                        } else if constexpr (std::is_same_v<T, DummySign>) {
                            if (m_outputFormat == OutputFormat::TAPROOT) {
                                return {1};
                            } else {
                                return {};
                            }
                        } else if constexpr (std::is_same_v<T, vector<unsigned char>>) {
                            return arg;
                        } else if constexpr (std::is_integral_v<T>) {
                            CScriptNum num(static_cast<int64_t>(arg));
                            return num.getvch();
                        } else {
                            abort();
                        }
                    },
                    elem));
            }
            sig.scriptWitness.stack.push_back(ToByteVector(m_scriptPubkey));
            if (this->m_outputFormat == OutputFormat::TAPROOT) {
                auto spentData = m_builder.GetSpendData();
                auto it = spentData.scripts.find(make_pair(ToByteVector(m_scriptPubkey), TAPROOT_LEAF_TAPSCRIPT));
                if (it == spentData.scripts.end()) abort();
                auto [_, control_blocks] = *it;
                sig.scriptWitness.stack.push_back(*control_blocks.begin());
            }
            break;

            // sig.scriptWitness.stack.push_back();
        default: throw std::runtime_error("invalid format");
        }
    }
};

class CInputTxBuilder
{
};

class CTestCase
{
public:
    std::string m_message;
    std::optional<ScriptError> m_expectError;

    CTransactionRef m_txStake;
    COutputTxBuilder<> m_builderStake;

    CTransactionRef m_txUtxo;
    COutputTxBuilder<> m_builderUtxo;

    CStakePromise m_promise;

    CTransactionRef m_txSpent;
    uint32_t m_inputSpent;

    std::function<COutputTxBuilder<>(CTestCase& tc)> m_stakeBuilderGetter;
    std::function<COutputTxBuilder<>(CTestCase& tc)> m_utxoBuilderGetter;
    std::function<CStakePromise(CTestCase& tc)> m_promiseMaker;
    std::function<tuple<CTransactionRef, uint32_t>(CTestCase& tc)> m_spentMaker;
    std::function<tuple<SignatureData, script::CSignerPickupChecker>(CTestCase& tc)> m_burnMaker;

    void Run()
    {
        BOOST_REQUIRE(m_stakeBuilderGetter && m_utxoBuilderGetter && m_promiseMaker && m_burnMaker);
        m_builderStake = m_stakeBuilderGetter(*this);
        m_builderUtxo = m_utxoBuilderGetter(*this);

        for (auto&& stakeFormat : span{allFormat}.subspan(0, 4)) {
            for (auto&& utxoFormat : span{allFormat}.subspan(0, 4)) {
                m_txStake = m_builderStake.Reset().WithOutputFormat(stakeFormat).Build();
                m_txUtxo = m_builderUtxo.Reset().WithOutputFormat(utxoFormat).Build();

                std::stringstream ss;
                ss << ", stake_fmt: " << OutputFormatToString(stakeFormat)
                << ", utxo_fmt: " << OutputFormatToString(utxoFormat);
                std::string msg_suffix = ss.str();

                std::map<Txid, CTransactionRef> txs;
                txs.emplace(m_txUtxo->GetHash(), m_txUtxo);

                m_promise = m_promiseMaker(*this);

                if (m_spentMaker) {
                    std::tie(m_txSpent, m_inputSpent) = m_spentMaker(*this);
                    txs.emplace(m_txSpent->GetHash(), m_txSpent);
                }

                // spent_txid, spent_vin, promise
                auto [signature_data, checker] = m_burnMaker(*this);

                ScriptError serror;
                bool result = VerifyScript(signature_data.scriptSig, m_txStake->vout[m_builderStake.m_nOutput].scriptPubKey, &signature_data.scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, checker, &serror);
                if (m_expectError) {
                    BOOST_CHECK_MESSAGE(!result, m_message + msg_suffix);
                    BOOST_CHECK_MESSAGE(*m_expectError == serror, m_message + msg_suffix);
                } else {
                    BOOST_CHECK_MESSAGE(result, m_message + msg_suffix);
                    BOOST_CHECK_MESSAGE(SCRIPT_ERR_OK == serror, m_message + msg_suffix);
                }
            }
        }
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(stakeburn_tests, UtocoinTestingSetup)

BOOST_AUTO_TEST_CASE(script_stakeburn)
{
    CKey keyA, keyB, keyC, keyD;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);
    keyC.MakeNewKey(true);
    keyD.MakeNewKey(true);

    
    CTestCase tc = {};
    tc.m_message = "burn";

    tc.m_stakeBuilderGetter = [keyA](CTestCase& tc) {
        return (COutputTxBuilder<>() << ToByteVector(keyA.GetPubKey().GetID()) << OP_STAKEBURN)
            .WithAmount(COIN * 10000)
            .WithInternalPubkey(XOnlyPubKey{keyA.GetPubKey()});
    };

    tc.m_utxoBuilderGetter = [keyA](CTestCase& tc) {
        return (COutputTxBuilder<>() << keyA.GetPubKey() << OP_CHECKDATSIGVERIFY << OP_CHECKSIG)
            .WithAmount(COIN * 10)
            .WithInternalPubkey(XOnlyPubKey{keyA.GetPubKey()});
    };

    tc.m_promiseMaker = [keyA, keyB](CTestCase& tc) -> CStakePromise {
        CStakePromise promise{
            {tc.m_txUtxo->GetHash(), tc.m_builderUtxo.m_nOutput},
            ToByteVector(keyB.GetPubKey().GetID()),
            {tc.m_txStake->GetHash(), tc.m_builderStake.m_nOutput},
        };
        promise.Sign(keyA);
        return promise;
    };

    tc.m_spentMaker = [keyC](CTestCase& tc) {
        CMutableTransaction txNew;
        uint32_t n = RandInt(5);
        txNew.vin.resize(5);
        txNew.vin[n] = CTxIn(tc.m_txUtxo->GetHash(), tc.m_builderUtxo.m_nOutput);

        SignatureData sig;
        tc.m_builderUtxo.MakeSignatureData(sig, {DummySign{}, DummySign{}, keyC.GetPubKey()});
        UpdateInput(txNew.vin[n], sig);
        return std::make_tuple(MakeTransactionRef(txNew), n);
    };

    tc.m_burnMaker = [keyB](CTestCase& tc) {
        std::map<Txid, CTransactionRef> txs = {{tc.m_txUtxo->GetHash(), tc.m_txUtxo}};
        Txid spendTxid = Txid::FromUint256(uint256::ZERO);
        if (tc.m_txSpent) {
            spendTxid = tc.m_txSpent->GetHash();
            txs.emplace(spendTxid, tc.m_txSpent);
        }
        script::CTransactionGetter::Instance().SetGetter([txs](const uint256& hash) -> CTransactionRef {
            if (auto it = txs.find(Txid::FromUint256(hash)); it != txs.end()) {
                return it->second;
            }
            return nullptr;
        });

        std::vector<unsigned char> vchPromise;
        tc.m_promise.Serialize(vchPromise);
        SignatureData signature_data;
        tc.m_builderStake.MakeSignatureData(signature_data, {ToByteVector(spendTxid.ToUint256()), vchPromise, DummySign{}, keyB.GetPubKey()});

        CMutableTransaction mtx;
        mtx.vin.emplace_back(tc.m_txStake->GetHash(), tc.m_builderStake.m_nOutput);
        UpdateInput(mtx.vin[0], signature_data);

        mtx.vout.emplace_back(tc.m_txStake->vout[tc.m_builderStake.m_nOutput].nValue, CScript() << OP_RETURN);

        script::CSignerPickupChecker checker(MakeTransactionRef(mtx), 0);
        checker.m_amount = tc.m_builderStake.m_nAmount;
        auto chain = CChainParams::RegTest(CChainParams::RegTestOptions{});
        checker.WithParams(chain->GetConsensus());

        return std::make_tuple(signature_data, checker);
    };
    tc.Run();

}



    // for (auto&& tc : vector<CTestCase>{
    //          {
    //              .m_message = "burn",
    //              .m_expectError = std::nullopt,
    //              .m_txStake = MakeTransactionRef(CMutableTransaction()),
    //              .m_stakeBuilderGetter = [keyA](CTestCase& tc) { return (COutputTxBuilder<>() << ToByteVector(keyA.GetPubKey().GetID()) << OP_STAKEBURN)
    //                                                                  .WithAmount(COIN * 10000)
    //                                                                  .WithInternalPubkey(XOnlyPubKey{keyA.GetPubKey()}); },
    //              .m_utxoBuilderGetter = [keyA](CTestCase& tc) { return (COutputTxBuilder<>() << keyA.GetPubKey() << OP_CHECKDATSIGVERIFY << OP_CHECKSIG)
    //                                                                 .WithAmount(COIN * 10)
    //                                                                 .WithInternalPubkey(XOnlyPubKey{keyA.GetPubKey()}); },
    //              .m_promiseMaker = [keyA, keyB](CTestCase& tc) -> CStakePromise {
    //                  CStakePromise promise{
    //                      {tc.m_txUtxo->GetHash(), tc.m_builderUtxo.m_nOutput},
    //                      ToByteVector(keyB.GetPubKey().GetID()),
    //                      {tc.m_txStake->GetHash(), tc.m_builderStake.m_nOutput},
    //                  };

    //                  promise.Sign(keyA);
    //                  return promise;
    //              },
    //              .m_spentMaker = [keyC](CTestCase& tc) {
    //                  CMutableTransaction txNew;
    //                  uint32_t n = RandInt(5);
    //                  txNew.vin.resize(5);
    //                  txNew.vin[n] = CTxIn(tc.m_txUtxo->GetHash(), tc.m_builderUtxo.m_nOutput);
    //                  // sigPayee, sigPayer, pubkeyB
    //                  SignatureData sig;
    //                  tc.m_builderUtxo.MakeSignatureData(sig, {DummySign{}, DummySign{}, keyC.GetPubKey()});
    //                  UpdateInput(txNew.vin[n], sig);

    //                  return std::make_tuple(MakeTransactionRef(txNew), n); },
    //              .m_burnMaker = [keyB](CTestCase& tc) {
    //                  map<Txid, CTransactionRef> txs = {{tc.m_txUtxo->GetHash(), tc.m_txUtxo}};
    //                  Txid spendTxid = Txid::FromUint256(uint256::ZERO);
    //                  if (tc.m_txSpent) {
    //                      spendTxid = tc.m_txSpent->GetHash();
    //                      txs.emplace(spendTxid, tc.m_txSpent);
    //                  }
    //                  script::CTransactionGetter::Instance().SetGetter([txs](const uint256 &hash)->CTransactionRef {
    //                      if ( auto it = txs.find(Txid::FromUint256(hash)); it != txs.end() ) {
    //                          return it->second;
    //                      }
    //                      return nullptr;
    //                  });

    //                  vector<unsigned char> vchPromsie;
    //                  tc.m_promise.Serialize(vchPromsie);
    //                  SignatureData signature_data;
    //                  tc.m_builderStake.MakeSignatureData(signature_data, {ToByteVector(spendTxid.ToUint256()), vchPromsie, DummySign{}, keyB.GetPubKey()});

    //                  CMutableTransaction mtx;
    //                  mtx.vin.emplace_back(tc.m_txStake->GetHash(), tc.m_builderStake.m_nOutput);
    //                  UpdateInput(mtx.vin[0], signature_data);

    //                  mtx.vout.emplace_back(tc.m_txStake->vout[tc.m_builderStake.m_nOutput].nValue, CScript() << OP_RETURN);

    //                  script::CSignerPickupChecker checker(MakeTransactionRef(mtx), 0);
    //                  checker.m_amount = tc.m_builderStake.m_nAmount;
    //                  auto chain = CChainParams::RegTest(CChainParams::RegTestOptions{});
    //                  checker.WithParams(chain->GetConsensus());

    //                  // let verifier known wich vin be processing
    //                  return make_tuple(signature_data, checker); },
    //          },
    //      }) {
    //     tc.Run();
    // }
// }
} // namespace utocoin::test

BOOST_AUTO_TEST_SUITE_END()