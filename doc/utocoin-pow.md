# UTOCoin Proof of Work

This document specifies the UTOCoin proof-of-work inputs that miners and
mining bridge implementations must reproduce. The authoritative
implementation is in `src/pow.cpp`, with network parameters in
`src/kernel/chainparams.cpp`.

## Overview

UTOCoin uses RandomX for proof-of-work validation while retaining the
Bitcoin-style 80-byte block header and double-SHA256 block identifier.

For each candidate block:

1. Serialize the block header exactly as `CBlockHeader`.
2. Derive the RandomX key for the candidate block height.
3. Compute `RandomX(key, serialized_header)`.
4. Interpret the RandomX output as a `uint256` and compare it with the target
   encoded by `nBits`.

The block hash used for `hashPrevBlock`, block locators, and block identity is
still the double-SHA256 hash of the serialized header. The RandomX hash is used
only for proof-of-work validation.

## Header Input

The RandomX input is the canonical serialized `CBlockHeader`:

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | `nVersion`, little-endian signed integer |
| 4 | 32 | `hashPrevBlock`, serialized `uint256` bytes |
| 36 | 32 | `hashMerkleRoot`, serialized `uint256` bytes |
| 68 | 4 | `nTime`, little-endian unsigned integer |
| 72 | 4 | `nBits`, little-endian unsigned integer |
| 76 | 4 | `nNonce`, little-endian unsigned integer |

The nonce offset for external workers is therefore byte `76` in the 80-byte
header. This is different from Monero-style RandomX mining blobs.

## Mainnet Parameters

| Parameter | Value |
| --- | --- |
| PoW algorithm | RandomX |
| Header input size | 80 bytes |
| Nonce offset | 76 |
| `powLimit` | `0000307fffffffffffffffffffffffffffffffffffffffffffffffffffffffff` |
| Target spacing | 60 seconds |
| Target timespan | 86400 seconds |
| Retarget interval | 1440 blocks |
| Retarget clamp | 0.25x to 4x actual timespan |
| `randomx_epoch` | 2048 blocks |
| `randomx_lag` | 64 blocks |
| `randomx_genesis_key` | `bitcoin/946065/000000000000000000003a4522741baed3efed5f150c66235ea80a37787f65e1` |
| Genesis block hash | `2be5d74003871900dd786760e42a03760526d9362332df4ed18b1ffd4a548455` |
| Genesis merkle root | `d5284bf000899b9b0b5dc6a8c0b1c67a9ed764071ddeec62fa86713d40c6719f` |
| Genesis `nTime` | `1776782829` |
| Genesis `nBits` | `1e307fff` |
| Genesis `nNonce` | `49253` |

Testnet and regtest use the same key schedule shape, but with their own
`powLimit` and `randomx_genesis_key` values from `chainparams.cpp`.

## RandomX Key Schedule

For candidate height `H`, epoch `E = randomx_epoch`, and lag
`L = randomx_lag`:

```text
if H < L:
    key = SHA256(randomx_genesis_key)
else:
    key_height = floor((H - L) / E) * E
    if key_height == 0:
        key = genesis block hash
    else:
        key = block hash at height key_height
```

With current mainnet values, heights `0..63` use
`SHA256(randomx_genesis_key)`, heights `64..2111` use the genesis block hash,
heights `2112..4159` use the block hash at height `2048`, and so on.

The key bytes passed into RandomX are the serialized `uint256` bytes, not the
display hex string byte order. For example, the displayed mainnet genesis hash
`2be5...8455` is passed to RandomX as bytes `554854...e52b`. The JSON vectors
include both display hex and byte-order hex for this reason.

## Difficulty And Validation

`nBits` encodes the proof-of-work target using Bitcoin compact encoding. A
block is valid only if:

```text
uint256(RandomX(key, serialized_header)) <= target(nBits)
```

The target must be positive, must not overflow, and must not exceed
`powLimit`. Difficulty retargeting follows the Bitcoin retarget formula with
UTOCoin mainnet's 60-second spacing and one-day timespan.

A node must have the key block ancestor available before it can validate the
RandomX proof for a header. During headers-first processing, a key block may be
an earlier header in the same batch, but it must precede the header being
validated.

## Mining Interface Notes

The current `getblocktemplate` response remains Bitcoin-style. It provides
`previousblockhash`, `target`, `bits`, `noncerange`, transactions, and coinbase
data, but it does not directly return a RandomX key. A miner or bridge must
derive the RandomX key from local chain state using the schedule above.

`submitblock` accepts the full serialized block. The submitted block is checked
by the same consensus path: block identity uses the double-SHA256 header hash,
and proof-of-work uses the RandomX hash over the serialized 80-byte header.

## Test Vectors

Machine-readable vectors are in
`src/test/data/utocoin_pow_vectors.json`. They cover:

- Current mainnet PoW parameters.
- RandomX key-height schedule boundaries.
- The mainnet genesis header and RandomX proof hash.
- A synthetic height-64 header using the genesis block hash as RandomX key.
