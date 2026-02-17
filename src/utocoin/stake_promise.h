// Copyright (c) 2025 The Utocoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __UTOCOIN_STAKE_PROMISE_H__
#define __UTOCOIN_STAKE_PROMISE_H__

#include "crypto/sha256.h"
#include "hash.h"
#include "primitives/transaction.h"
#include "span.h"
#include "uint256.h"
#include <format>
#include <iostream>
#include <sstream>

namespace utocoin {

using namespace std;

typedef vector<unsigned char> valtype;

template <typename T>
concept PirvateKey = requires(T obj, const uint256& hash, std::vector<unsigned char>& vchSig) {
    { obj.Sign(hash, vchSig) };
};

template <typename T>
concept PublicKey =
    requires(const vector<unsigned char>& vch) {
        T{vch};
    } &&
    requires(T obj, const uint256& hash, const std::vector<unsigned char>& vchSig) {
        { obj.Verify(hash, vchSig) } -> std::same_as<bool>;
    };

// Stake can be wrapped by Taproot. In a Taproot output
// the internal public key must not have a corresponding private key, for example XOnlyPubKey::NUMS_H
// the Merkle tree typically contains only one leaf node, which represents the stake unlock script.
// Therefore, the payee can fully reconstruct the Taproot structure (and the expected tweaked public key) using the internal public key and the stake script.
// This allows them to compare their locally regenerated public key with the public key on the blockchain, confirming they've correctly identified the funds.

class CStakePromise
{
public:
    enum {
        WITH_SCRIPT = 1 << 0,
        WITH_INTERNAL_KEY = 1 << 1,
    };

public:
    COutPoint m_utxo;
    valtype m_payee_anchor;
    COutPoint m_stakeutxo;
    valtype m_pubkey;
    valtype m_signature;

protected:
    void SerializeWithoutSignature(valtype& vchData) const
    {
        if (AnyNullWithoutSignature()) {
            throw std::runtime_error("some member there are empty");
        }

        auto s = CScript() << Flags() << m_utxo.hash << m_utxo.n << m_payee_anchor << m_stakeutxo.hash << m_stakeutxo.n;
        vchData.clear();
        vchData.insert(vchData.end(), s.begin(), s.end());
    }

    uint32_t Flags() const
    {
        uint32_t flags = 0;
        return flags;
    }

public:
    CStakePromise() { SetNull(); }

    CStakePromise(const vector<unsigned char>& vchData)
    {
        Deserialize(vchData);
    }

    CStakePromise(const COutPoint& utxo, const valtype& payee_anchor, const COutPoint& stakeutxo, const valtype& pubkey = valtype(), const valtype& m_signature = valtype())
        : m_utxo(utxo), m_payee_anchor(payee_anchor), m_stakeutxo(stakeutxo), m_pubkey(pubkey), m_signature(m_signature) {}

    CStakePromise(const CStakePromise& other)
    {
        m_utxo = other.m_utxo;
        m_payee_anchor = other.m_payee_anchor;
        m_stakeutxo = other.m_stakeutxo;
        m_pubkey = other.m_pubkey;
        m_signature = other.m_signature;
    }

    CStakePromise(CStakePromise&& other) noexcept : m_utxo(std::move(other.m_utxo)), m_payee_anchor(std::move(other.m_payee_anchor)), m_stakeutxo(std::move(other.m_stakeutxo)),
                                                    m_pubkey(std::move(other.m_pubkey)), m_signature(std::move(other.m_signature))
    {
        other.SetNull();
    }

    void SetNull()
    {
        m_utxo.SetNull();
        m_payee_anchor.clear();
        m_stakeutxo.SetNull();
        m_pubkey.clear();
        m_signature.clear();
    }

    bool IsNull() const
    {
        return m_utxo.IsNull() && m_payee_anchor.empty() && m_stakeutxo.IsNull() && m_pubkey.empty() && m_signature.empty();
    }

    bool AnyNull() const
    {
        return AnyNullWithoutSignature() || m_pubkey.empty() || m_signature.empty();
    }

    bool AnyNullWithoutSignature() const
    {
        return m_utxo.IsNull() || m_payee_anchor.empty() || m_stakeutxo.IsNull();
    }

    void Serialize(valtype& vchData) const
    {
        if (AnyNull()) {
            throw std::runtime_error("some member there are empty");
        }
        auto s = CScript() << Flags() << m_utxo.hash << m_utxo.n << m_payee_anchor << m_stakeutxo.hash << m_stakeutxo.n;
        s << m_pubkey << m_signature;
        vchData.clear();
        vchData.insert(vchData.end(), s.begin(), s.end());
    }

    void Deserialize(const valtype& vchData)
    {
        if (!vchData.size()) {
            SetNull();
            return;
        }

        CScript script(vchData.begin(), vchData.end());
        CScript::const_iterator pc = script.begin();

        auto _inner_pickup_data = [&pc, &script](opcodetype& opcode, valtype& vchData) {
            if (!script.GetOp(pc, opcode, vchData)) throw std::runtime_error("bad op code");

            if (!((opcode >= OP_0 && opcode <= OP_PUSHDATA4) || (opcode >= OP_1 && opcode <= OP_16))) {
                std::stringstream ss;
                ss << "invalid opcode " << int(opcode);
                throw std::runtime_error(ss.str());
            }
        };

        auto pickup_data = [_inner_pickup_data]() -> valtype {
            valtype vchData;
            opcodetype opcode;
            _inner_pickup_data(opcode, vchData);
            return vchData;
        };

        auto pickup_uint32 = [_inner_pickup_data]() -> uint32_t {
            valtype vchData;
            opcodetype opcode;
            _inner_pickup_data(opcode, vchData);

            if (opcode == OP_0) {
                return 0;
            }
            if (opcode >= OP_1 && opcode <= OP_16) {
                return CScript::DecodeOP_N(opcode);
            }
            assert(vchData.size() > 0);
            CScriptNum num(vchData, false);
            return num.getint();
        };

        pickup_uint32();  //flags, not used here.
        // utxo.hash
        m_utxo.hash = Txid::FromUint256(uint256(Span<const unsigned char>(pickup_data())));
        // utxo.N
        m_utxo.n = pickup_uint32();
        // m_toaddr
        m_payee_anchor = pickup_data();
        // stakeutxo.hash
        m_stakeutxo.hash = Txid::FromUint256(uint256(Span<const unsigned char>(pickup_data())));
        // stakeutxo.N
        m_stakeutxo.n = pickup_uint32();
        // pubkey
        m_pubkey = pickup_data();
        // signature
        m_signature = pickup_data();

        // check fully consumed
        if (script.end() - pc > 0) throw std::runtime_error("error data for promise");
    }

    uint256 Hash() const
    {
        valtype data;
        SerializeWithoutSignature(data);
        return ::Hash(data);
    }

    operator valtype() const
    {
        valtype result;
        Serialize(result);
        return result;
    }

    // operator std::span<const unsigned char>() const
    // {
    //     return std::span<const unsigned char>(valtype(*this));
    // }

    bool operator==(const CStakePromise& other)
    {
        return m_utxo == other.m_utxo && m_payee_anchor == other.m_payee_anchor && m_stakeutxo == other.m_stakeutxo &&
               m_pubkey == other.m_pubkey && m_signature == other.m_signature;
    }

    bool operator!=(const CStakePromise& other)
    {
        return !(*this == other);
    }

    CStakePromise& operator=(const CStakePromise& other)
    {
        m_utxo = other.m_utxo;
        m_payee_anchor = other.m_payee_anchor;
        m_stakeutxo = other.m_stakeutxo;
        m_pubkey = other.m_pubkey;
        m_signature = other.m_signature;
        return *this;
    }

    template <PirvateKey keytype>
    void Sign(const keytype& key)
    {
        uint256 hash = Hash();
        m_signature.clear();

        if (!key.Sign(hash, m_signature)) {
            throw std::runtime_error("sign promise got error");
        }

        auto _pubKey = key.GetPubKey();
        m_pubkey = valtype(_pubKey.begin(), _pubKey.end());
    }

    template <PublicKey pubkey_type>
    bool Verify() const
    {
        pubkey_type pubkey(m_pubkey);
        uint256 hash = Hash();
        return pubkey.Verify(hash, m_signature);
    }
};
} // namespace utocoin

#endif