// Copyright (c) 2026 The Utocoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_RANDOMX_HASH_H
#define BITCOIN_CRYPTO_RANDOMX_HASH_H

#include <span.h>
#include <uint256.h>

uint256 RandomXHash(Span<const unsigned char> key, Span<const unsigned char> input);

#endif // BITCOIN_CRYPTO_RANDOMX_HASH_H
