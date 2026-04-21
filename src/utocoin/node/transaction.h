// Copyright (c) 2025 The Utocoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef __UTOCOIN_NODE_TRANSACTION_H__
#define __UTOCOIN_NODE_TRANSACTION_H__

#include <primitives/transaction.h>
#include <index/txindex.h>

namespace utocoin::node {

/**
 * Return transaction with a given hash in txindex.
 * @param[in]  hash            The txid
 * @param[out] hashBlock       The block hash, if the tx was found via txindex
 * @returns                    The tx if found, otherwise nullptr
 */
CTransactionRef GetTransaction(const uint256& hash, uint256& hashBlock);

CTransactionRef GetTransaction(const uint256& hash);

} // namespace utocoin::node


#endif // __UTOCOIN_NODE_TRANSACTION_H__