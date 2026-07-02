#!/usr/bin/env python3
# Copyright (c) 2016-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test version bits warning system.

Generate chains with block versions that appear to be signalling unknown
soft-forks, and test that warning alerts are generated.
"""
import os
import re

from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import msg_block
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework

# utocoin regtest: nMinerConfirmationWindow = 1440,
# nRuleChangeActivationThreshold = 1080 (75%).
VB_PERIOD = 1440          # versionbits period length for regtest
VB_THRESHOLD = 1080       # versionbits activation threshold for regtest
VB_TOP_BITS = 0x20000000
VB_UNKNOWN_BIT = 27       # Choose a bit unassigned to any deployment
VB_UNKNOWN_VERSION = VB_TOP_BITS | (1 << VB_UNKNOWN_BIT)

WARN_UNKNOWN_RULES_ACTIVE = f"Unknown new rules activated (versionbit {VB_UNKNOWN_BIT})"
VB_PATTERN = re.compile("Unknown new rules activated.*versionbit")

class VersionBitsWarningTest(BitcoinTestFramework):
    def set_test_params(self):
        # utocoin regtest BIP9 window is 1440 (vs BTC 144); this test mines
        # several windows of RandomX blocks, so the default 30s RPC timeout
        # is too short for the per-generate batch calls.
        self.rpc_timeout *= 20
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.alert_filename = os.path.join(self.options.tmpdir, "alert.txt")
        # Open and close to create zero-length file
        with open(self.alert_filename, 'w', encoding='utf8'):
            pass
        self.extra_args = [[f"-alertnotify=echo %s >> \"{self.alert_filename}\""]]
        self.setup_nodes()

    def send_blocks_with_version(self, peer, numblocks, version):
        """Submit numblocks RandomX-mined blocks with the given version.

        Originally this used the supplied P2PInterface 'peer' to send blocks,
        but utocoin's 1440-block BIP9 window means we have to submit > 1000
        custom-version blocks per call. Under RandomX that takes long enough
        that the test peer connection times out or trips the daemon's
        anti-DoS Misbehaving threshold. We submit via the submitblock RPC
        instead, which is functionally equivalent (the daemon goes through
        the same AcceptBlock path) but does not depend on a live P2P link.
        The 'peer' parameter is kept for API compatibility.

        When the chain crosses a RandomX epoch boundary (the proof-of-work
        key changes every randomx_epoch=2048 blocks past randomx_lag=64),
        we recompute rx_seed locally so the test's solve() matches what the
        daemon expects.
        """
        _ = peer  # unused
        node = self.nodes[0]
        RANDOMX_EPOCH = 2048
        RANDOMX_LAG = 64

        def key_height(block_height):
            if block_height < RANDOMX_LAG:
                return None  # uses RandomXGenesisKeyHash, not a block hash
            return ((block_height - RANDOMX_LAG) // RANDOMX_EPOCH) * RANDOMX_EPOCH

        def seed_for(block_height):
            kh = key_height(block_height)
            if kh is None:
                # pre-lag: daemon uses a non-block-hash seed; ask it.
                return node.getblockheader(node.getblockhash(max(0, block_height - 1))).get("rx_seed")
            return node.getblockhash(kh)

        tip = node.getbestblockhash()
        height = node.getblockcount()
        block_time = node.getblockheader(tip)["time"] + 1
        current_key_height = key_height(height + 1)
        rx_seed = seed_for(height + 1)
        tip = int(tip, 16)

        for _ in range(numblocks):
            next_height = height + 1
            new_key_height = key_height(next_height)
            if new_key_height != current_key_height:
                rx_seed = seed_for(next_height)
                current_key_height = new_key_height

            block = create_block(tip, create_coinbase(next_height), block_time, version=version, rx_seed=rx_seed)
            block.solve(rx_seed)
            result = node.submitblock(hexdata=block.serialize().hex())
            assert result is None, f"submitblock(height={next_height}) -> {result}"
            block_time += 1
            height = next_height
            tip = block.sha256

    def versionbits_in_alert_file(self):
        """Test that the versionbits warning has been written to the alert file."""
        with open(self.alert_filename, 'r', encoding='utf8') as f:
            alert_text = f.read()
        return VB_PATTERN.search(alert_text) is not None

    def run_test(self):
        node = self.nodes[0]

        node_deterministic_address = node.get_deterministic_priv_key().address
        # Mine one period worth of blocks first (utocoin regtest's 1440-block
        # window means this takes some time under RandomX). We add the P2P
        # peer afterwards so the connection doesn't time out during mining.
        self.generatetoaddress(node, VB_PERIOD, node_deterministic_address)

        peer = node.add_p2p_connection(P2PInterface())

        self.log.info("Check that there is no warning if previous VB_BLOCKS have <VB_THRESHOLD blocks with unknown versionbits version.")
        # Build one period of blocks with < VB_THRESHOLD blocks signaling some unknown bit
        self.send_blocks_with_version(peer, VB_THRESHOLD - 1, VB_UNKNOWN_VERSION)
        self.generatetoaddress(node, VB_PERIOD - VB_THRESHOLD + 1, node_deterministic_address)

        # Check that we're not getting any versionbit-related errors in get*info()
        assert not VB_PATTERN.match(",".join(node.getmininginfo()["warnings"]))
        assert not VB_PATTERN.match(",".join(node.getnetworkinfo()["warnings"]))

        # Build one period of blocks with VB_THRESHOLD blocks signaling some unknown bit
        self.send_blocks_with_version(peer, VB_THRESHOLD, VB_UNKNOWN_VERSION)
        self.generatetoaddress(node, VB_PERIOD - VB_THRESHOLD, node_deterministic_address)

        self.log.info("Check that there is a warning if previous VB_BLOCKS have >=VB_THRESHOLD blocks with unknown versionbits version.")
        # Mine a period worth of expected blocks so the generic block-version warning
        # is cleared. This will move the versionbit state to ACTIVE.
        self.generatetoaddress(node, VB_PERIOD, node_deterministic_address)

        # Stop-start the node. This is required because bitcoind will only warn once about unknown versions or unknown rules activating.
        self.restart_node(0)

        # Generating one block guarantees that we'll get out of IBD
        self.generatetoaddress(node, 1, node_deterministic_address)
        self.wait_until(lambda: not node.getblockchaininfo()['initialblockdownload'])
        # Generating one more block will be enough to generate an error.
        self.generatetoaddress(node, 1, node_deterministic_address)
        # Check that get*info() shows the versionbits unknown rules warning
        assert WARN_UNKNOWN_RULES_ACTIVE in ",".join(node.getmininginfo()["warnings"])
        assert WARN_UNKNOWN_RULES_ACTIVE in ",".join(node.getnetworkinfo()["warnings"])
        # Check that the alert file shows the versionbits unknown rules warning
        self.wait_until(lambda: self.versionbits_in_alert_file())

if __name__ == '__main__':
    VersionBitsWarningTest(__file__).main()
