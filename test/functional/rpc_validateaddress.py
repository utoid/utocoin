#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test validateaddress for main chain"""

from test_framework.test_framework import BitcoinTestFramework

from test_framework.util import assert_equal

INVALID_DATA = [
    # BIP 173
    (
        "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
        "Invalid or unsupported Segwit (Bech32) or Base58 encoding.",  # Invalid hrp
        [],
    ),
    ("uto1qw508d6qejxtdg4y5r3zarvary0c5xw7k0ua4t5", "Invalid Bech32 checksum", [42]),
    (
        "UTO13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KSWM2FK",
        "Version 1+ witness address must use Bech32m checksum",
        [],
    ),
    (
        "uto1rqq4qjhu9",
        "Version 1+ witness address must use Bech32m checksum",  # Invalid program length
        [],
    ),
    
    ("uto1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kwvehgw", "Version 1+ witness address must use Bech32m checksum", []),  # Invalid program length (v1 + 40 bytes with Bech32 checksum)
    ("UTO1QW508D6QEJXTDG4Y5R3ZARVARYVUSEC6N", "Invalid Bech32 v0 address program size (16 bytes), per BIP141", []),  # Invalid Bech32 v0 address program size (16 bytes), per BIP141
    
    ("tb1QRY9X8Gf2tvdw0s3jn54khce6mua7qpzra5wcmd", "Invalid or unsupported Segwit (Bech32) or Base58 encoding.", []),  # tb1, Mixed case
    ("UTO1Q8W4UYTJEPG0KA9VN6ZFSH7XD5MR23CQ8W4UyTJEPG0KA9VN6ZFSH5YXCRV", "Invalid character or mixed case", [40]),  # bc1, Mixed case, not in BIP 173 test vectors

    ("uto1zw508d6qejxtdg4y5r3zarvaryvx60usy", "Version 1+ witness address must use Bech32m checksum", []),  # Version 1+ witness address must use Bech32m checksum (Wrong padding)

    ("tb1qpzry9x8gf2tvdw0s3jn54khce6mua7qpzrz6jr6m", "Invalid or unsupported Segwit (Bech32) or Base58 encoding.", []),  # tb1, Non-zero padding in 8-to-5 conversion
    ("uto175nwm7", "Empty Bech32 data section", []),  # Empty Bech32 data section

    ("tc1prp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qympy6f", "Invalid or unsupported Segwit (Bech32) or Base58 encoding.", []),  # Invalid human-readable part
    ("uto1prp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qfcny8e", "Version 1+ witness address must use Bech32m checksum", []),  # Invalid checksum (Bech32 instead of Bech32m)

    ("aa1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6h60q0", "Invalid or unsupported Segwit (Bech32) or Base58 encoding.", []),  # tb1, Invalid checksum (Bech32 instead of Bech32m)

    ("UTO1PRP33G0Q5C5TXSP9ARYSRX4K6ZDKFS4NCE4XJ0GDCCCEFVPYSXF3QFCNY8E", "Version 1+ witness address must use Bech32m checksum", []),  # Invalid checksum (Bech32 instead of Bech32m)
    ("uto1qw508d6qejxtdg4y5r3zarvary0c5xw7k6qdewt", "Version 0 witness address must use Bech32 checksum", []),  # Invalid checksum (Bech32m instead of Bech32)

    ("aa1qxvjc79t3hay2skurf04mzgw56p8dneqx05mkh7", "Invalid or unsupported Segwit (Bech32) or Base58 encoding.", []),  # tb1, Invalid checksum (Bech32m instead of Bech32)
    ("uto1p257fnagju83mxs690eywcrdhzvkpt4q257fnagju83mxs690eywcaqbs0c", "Invalid Base 32 character", [59]),  # Invalid Base 32 character
    ("UTO13FJM9WHP2NUX0CZT5A8SERV47G36YDKQFF7X4FS", "Invalid Bech32 address witness version", []),  # Invalid Bech32 address witness version

    ("uto1pqqycsuz7", "Invalid Bech32 address program size (1 byte)", []),  # Invalid Bech32 address program size (1 byte)
    ("uto1prp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qqqqqqqqqqqqqqqsvpl5t", "Invalid Bech32 address program size (41 bytes)", []),  # Invalid Bech32 address program size (41 bytes)
    ("UTO1QW508D6QEJXTDG4Y5R3ZARVARYVUSEC6N", "Invalid Bech32 v0 address program size (16 bytes), per BIP141", []),  # Invalid Bech32 v0 address program size (16 bytes), per BIP141

    ("aa1psp3zjrny594xk8hgcfe26tmvudaw70qsp3zjrny594xk8hgcfe26ul4y4z", "Invalid or unsupported Segwit (Bech32) or Base58 encoding.", []),  # tb1, Mixed case
    ("uto1p9203pk34v", "Invalid padding in Bech32 data section", []),  # Invalid padding in Bech32 data section (zero padding of more than 4 bits)
    ("aa1p7aum6echk45nj3s0wdvt2fg8x9yrzpq7alg7nt9", "Invalid or unsupported Segwit (Bech32) or Base58 encoding.", []),  # tb1, Non-zero padding in 8-to-5 conversion
    ("uto175nwm7", "Empty Bech32 data section", []),  # Empty Bech32 data section
]
VALID_DATA = [
    # BIP 350
    (
        "uto1qw508d6qejxtdg4y5r3zarvary0c5xw7k0ua4tf",
        "0014751e76e8199196d454941c45d1b3a323f1433bd6",
    ),
    # (
    #   "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
    #   "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
    # ),
    (
        "uto1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qknrp68",
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
    ),
    (
        "uto1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kmsfmdv",
        "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
    ),
    ("UTO1SW50QMMDTPX", "6002751e"),
    ("uto1zw508d6qejxtdg4y5r3zarvaryvnxls4x", "5210751e76e8199196d454941c45d1b3a323"),
    # (
    #   "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
    #   "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    # ),
    (
        "uto1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvses69t0ma",
        "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
   # (
    #   "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
    #   "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    # ),
    (
        "uto1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsessjtxrp",
        "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ),
    (
        "uto1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqva7gye",
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ),
    # PayToAnchor(P2A)
    (
        "uto1pfeesr4j0aa",
        "51024e73",
    ),
]


class ValidateAddressMainTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.chain = ""  # main
        self.num_nodes = 1
        self.extra_args = [["-prune=899"]] * self.num_nodes

    def check_valid(self, addr, spk):
        info = self.nodes[0].validateaddress(addr)
        assert_equal(info["isvalid"], True)
        assert_equal(info["scriptPubKey"], spk)
        assert "error" not in info
        assert "error_locations" not in info

    def check_invalid(self, addr, error_str, error_locations):
        res = self.nodes[0].validateaddress(addr)
        assert_equal(res["isvalid"], False)
        assert_equal(res["error"], error_str)
        assert_equal(res["error_locations"], error_locations)

    def test_validateaddress(self):
        for (addr, error, locs) in INVALID_DATA:
            self.check_invalid(addr, error, locs)
        for (addr, spk) in VALID_DATA:
            self.check_valid(addr, spk)

    def run_test(self):
        self.test_validateaddress()


if __name__ == "__main__":
    ValidateAddressMainTest(__file__).main()
