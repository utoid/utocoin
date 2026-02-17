// Copyright (c) 2025 The Utocoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __UTOCOIN_UTOCOIN_SCRIPT_TRANSACTION_GETTER_H__
#define __UTOCOIN_UTOCOIN_SCRIPT_TRANSACTION_GETTER_H__

#include <functional>
#include <primitives/transaction.h>

namespace utocoin::script {

class CTransactionGetter
{
private:
    static CTransactionGetter _instance;

    CTransactionGetter() {};

    std::function<CTransactionRef(const uint256& hash)> m_getter;

public:
    static CTransactionGetter& Instance()
    {
        return _instance;
    };
    CTransactionGetter(const CTransactionGetter&) = delete;
    CTransactionGetter& operator=(const CTransactionGetter&) = delete;

    void SetGetter(const std::function<CTransactionRef(const uint256& hash)>& getter)
    {
        m_getter = getter;
    }

    CTransactionRef GetTransaction(const uint256& hash)
    {
        return m_getter(hash);
    }
};

} // namespace utocoin::script

#endif