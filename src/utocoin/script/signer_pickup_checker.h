// Copyright (c) 2025 The Utocoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __UTOCOIN_UTOCOIN_SCRIPT_SIGNER_PICKUP_CHECKER_H__
#define __UTOCOIN_UTOCOIN_SCRIPT_SIGNER_PICKUP_CHECKER_H__

#include <script/interpreter.h>

namespace utocoin::script {
class CSignerPickupChecker : public BaseSignatureChecker
{
public:
    CTransactionRef m_tx;
    int n;
    mutable std::vector<std::vector<unsigned char>> m_signers;
    CAmount m_amount;

public:
    explicit CSignerPickupChecker() {}

    CSignerPickupChecker(CTransactionRef tx, int n) : m_tx(tx), n(n) {}

    CTransactionRef VerifingTransaction() const override { return m_tx; }
    COutPoint VerifyingPrevout() const override { return m_tx->vin[n].prevout; };
    CAmount GetAmount() const override {return m_amount;}

    bool CheckECDSASignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override
    {
        m_signers.push_back(vchPubKey);
        return true;
    }

    bool CheckSchnorrSignature(Span<const unsigned char> sig, Span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror = nullptr) const override
    {
        m_signers.emplace_back(pubkey.begin(), pubkey.end());
        return true;
    }

    bool CheckLockTime(const CScriptNum& nLockTime) const override
    {
        return true;
    }

    bool CheckSequence(const CScriptNum& nSequence) const override
    {
        return true;
    }
};

} // namespace utocoin::script

#endif