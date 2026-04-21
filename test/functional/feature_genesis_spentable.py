#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import (
    CScript,
    OP_1, OP_EQUAL,
    OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG,
    LegacySignatureHash, SIGHASH_ALL
)
from test_framework.messages import CTransaction
from test_framework.key import ECKey
from decimal import Decimal
import hashlib, io


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(b: bytes) -> str:
    n, res = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        res = B58[r] + res
    pad = 0
    for c in b:
        if c == 0: pad += 1
        else: break
    return "1" * pad + res

def b58check(payload: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)

def hex_to_wif(privkey_hex: str, compressed=True, testnet=True):
    raw = bytes.fromhex(privkey_hex)
    prefix = b'\xEF' if testnet else b'\x80'
    payload = prefix + raw
    if compressed:
        payload += b"\x01"
    return b58check(payload)

class GenesisSpendableTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-regtest', '-acceptnonstdtxn', '-disablewallet=0']]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Verifying genesis block information...")
        genesis_hash = "7c689a1b2cdee9b1c2e79e08ba2414bb6e0f611c505a677917fc6b4b61aab4cd"
        privkey_hex = "6334dc1f7baa091f3ca23252bec38023ccc90cd25accda86561cb80e2c914941"
        wif_key = hex_to_wif(privkey_hex)

        node.createwallet("genesis_test", load_on_startup=False)
        wallet = node.get_wallet_rpc("genesis_test")
        wallet.importprivkey(wif_key)

        block = node.getblock(genesis_hash, 2)
        coinbase_tx = block["tx"][0]
        txid = coinbase_tx["txid"]
        self.log.info(f"Genesis txid: {txid}")
        self.log.info(f"Genesis has {len(coinbase_tx['vout'])} outputs")

        dest_addr = wallet.getnewaddress()

        # Spend vout[1] (nonstandard)
        self.log.info("Spending vout[1] (nonstandard 51 OP_EQUAL)...")
        amount1 = coinbase_tx["vout"][1]["value"]
        raw1 = node.createrawtransaction(
            [{"txid": txid, "vout": 1}],
            {dest_addr: amount1 - Decimal("0.00001")}
        )

        tx1 = CTransaction()
        tx1.deserialize(io.BytesIO(bytes.fromhex(raw1)))
        tx1.vin[0].scriptSig = CScript([OP_1])
        raw1_signed = tx1.serialize().hex()
        txid1 = node.sendrawtransaction(raw1_signed)
        self.log.info(f"Sent txid1: {txid1}")

        # Spend vout[2] (P2PKH)
        self.log.info("Spending vout[2] (P2PKH)...")
        amount2 = coinbase_tx["vout"][2]["value"]

        key = ECKey()
        key.set(bytes.fromhex(privkey_hex), compressed=True)
        pubkey = key.get_pubkey().get_bytes()

        raw2 = node.createrawtransaction(
            [{"txid": txid, "vout": 2}],
            {dest_addr: amount2 - Decimal("0.00001")}
        )
        tx2 = CTransaction()
        tx2.deserialize(io.BytesIO(bytes.fromhex(raw2)))

        script_pubkey = CScript(bytes.fromhex(
            "76a91469b7242b4dd0731ffb217844e6936b7243e9df7188ac"
        ))

        sighash_val = LegacySignatureHash(script_pubkey, tx2, 0, SIGHASH_ALL)
        if isinstance(sighash_val, tuple):
            sighash_val = sighash_val[0]
        if isinstance(sighash_val, int):
            sighash_bytes = sighash_val.to_bytes(32, 'big')
        else:
            sighash_bytes = bytes(sighash_val)

        sig = key.sign_ecdsa(sighash_bytes) + bytes([SIGHASH_ALL])
        tx2.vin[0].scriptSig = CScript([sig, pubkey])
        raw2_signed = tx2.serialize().hex()
        txid2 = node.sendrawtransaction(raw2_signed)
        self.log.info(f"Sent txid2: {txid2}")

        # Confirm both transactions in a new block
        mempool = node.getrawmempool()
        assert txid1 in mempool and txid2 in mempool
        self.log.info("Mining a block to confirm genesis spends...")
        try:
            addr = node.getnewaddress()
            node.generatetoaddress(nblocks=1, address=addr, called_by_framework=True)
        except TypeError:
            node.generate(1)

        mempool_after = node.getrawmempool()
        assert txid1 not in mempool_after and txid2 not in mempool_after
        self.log.info("Both genesis spend transactions confirmed.")

        # Verify both tx are in the latest block
        blockhash = node.getbestblockhash()
        block = node.getblock(blockhash)
        txs_in_block = set(block["tx"])
        self.log.info(f"Latest block: {blockhash}")
        assert txid1 in txs_in_block, f"txid1 {txid1} not found in block {blockhash}"
        assert txid2 in txs_in_block, f"txid2 {txid2} not found in block {blockhash}"
        self.log.info(f"Both genesis spend txs included in block {blockhash[:8]}...{blockhash[-8:]}")
        self.log.info("Test completed successfully.")


if __name__ == '__main__':
    GenesisSpendableTest(__file__).main()

