#include "init.h"
#include <utocoin/node/transaction.h>
#include <utocoin/script/transaction_getter.h>

namespace utocoin {

void Init()
{
    script::CTransactionGetter::Instance().SetGetter([](const uint256& hash) -> CTransactionRef {
        return ::utocoin::node::GetTransaction(hash);
    });
}

} // namespace utocoin