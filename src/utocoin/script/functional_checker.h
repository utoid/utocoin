// Copyright (c) 2025 The Utocoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __UTOCOIN_UTOCOIN_FUNCTIONAL_CHECKER_H__
#define __UTOCOIN_UTOCOIN_FUNCTIONAL_CHECKER_H__

#include <script/interpreter.h>

namespace utocoin::script {

using FnCheckECDSASignature = std::function<bool(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion)>;
using FnCheckSchnorrSignature = std::function<bool(Span<const unsigned char> sig, Span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror)>;
using FnCheckLockTime = std::function<bool(const CScriptNum& nLockTime)>;
using FnCheckSequence = std::function<bool(const CScriptNum& nLockTime)>;
using FnSighashBlender = std::function<void(uint256& hash)>;

class CFunctionalChecker : public BaseSignatureChecker
{
public:
    const BaseSignatureChecker& m_parent;

    FnCheckECDSASignature m_fnCheckECDSASignature;
    FnCheckSchnorrSignature m_fnCheckSchnorrSignature;
    FnCheckLockTime m_fnCheckLockTime;
    FnCheckSequence m_fnCheckSequence;
    FnSighashBlender m_fnSighashBlender;

    CFunctionalChecker(const BaseSignatureChecker& parent,
                       FnCheckECDSASignature fnCheckECDSASignature = nullptr,
                       FnCheckSchnorrSignature fnCheckSchnorrSignature = nullptr,
                       FnCheckLockTime fnCheckLockTime = nullptr,
                       FnCheckSequence fnCheckSequence = nullptr,
                       FnSighashBlender fnSighashBlender = nullptr) : m_parent(parent), m_fnCheckECDSASignature(fnCheckECDSASignature),
                                                                      m_fnCheckSchnorrSignature(fnCheckSchnorrSignature), m_fnCheckLockTime(fnCheckLockTime),
                                                                      m_fnCheckSequence(fnCheckSequence), m_fnSighashBlender(fnSighashBlender)
    {
    }

    bool CheckECDSASignature(const std::vector<unsigned char>& scriptSig, const std::vector<unsigned char>& vchPubKey, const CScript& scriptCode, SigVersion sigversion) const override
    {
        return m_fnCheckECDSASignature ?
                   m_fnCheckECDSASignature(scriptSig, vchPubKey, scriptCode, sigversion) :
                   m_parent.CheckECDSASignature(scriptSig, vchPubKey, scriptCode, sigversion);
    }

    bool CheckSchnorrSignature(Span<const unsigned char> sig, Span<const unsigned char> pubkey, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError* serror = nullptr) const override
    {
        return m_fnCheckSchnorrSignature ?
                   m_fnCheckSchnorrSignature(sig, pubkey, sigversion, execdata, serror) :
                   m_parent.CheckSchnorrSignature(sig, pubkey, sigversion, execdata, serror);
    }

    bool CheckLockTime(const CScriptNum& nLockTime) const override
    {
        return m_fnCheckLockTime ?
                   m_fnCheckLockTime(nLockTime) :
                   m_parent.CheckLockTime(nLockTime);
    }

    bool CheckSequence(const CScriptNum& nSequence) const override
    {
        return m_fnCheckSequence ?
                   m_fnCheckSequence(nSequence) :
                   m_parent.CheckSequence(nSequence);
    }

    void SighashBlender(uint256& hash) const override
    {
        m_fnSighashBlender ? m_fnSighashBlender(hash) : m_parent.SighashBlender(hash);
    }
};

} // namespace utocoin::script

#endif // __UTOCOIN_UTOCOIN_FUNCTIONAL_CHECKER_H
