#include "transaction.h"
#include <index/txindex.h>

namespace utocoin::node {

CTransactionRef GetTransaction(const uint256& hash, uint256& hashBlock)
{
    if (g_txindex) {
        CTransactionRef tx;
        uint256 block_hash;
        if (g_txindex->FindTx(hash, block_hash, tx)) {
            hashBlock = block_hash;
            return tx;
        }
    }
    return nullptr;
}

CTransactionRef GetTransaction(const uint256& hash) {
    uint256 hashBlock;
    return GetTransaction(hash, hashBlock);
}

}