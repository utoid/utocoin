#!/usr/bin/env python3
# Copyright (c) 2026 The Utocoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""ctypes binding to librandomx for the functional test framework.

Mirrors the C++ helper in src/crypto/randomx_hash.cpp: a small key->VM cache
so that solve() loops do not pay the cache/VM init cost per nonce. Builds of
the project produce librandomx.{so,dylib,dll} via the shared target added in
src/randomx/CMakeLists.txt; this module locates that artifact and exposes a
single function::

    randomx_hash(key: bytes, header: bytes) -> bytes  # 32-byte digest
"""

import ctypes
import hashlib
import os
import platform
import sys
import threading
from collections import OrderedDict

RANDOMX_HASH_SIZE = 32

# Regtest consensus params for RandomX seed derivation.
# Mirrors src/kernel/chainparams.cpp regtest section + GetRandomXKey logic.
REGTEST_RANDOMX_LAG = 64
REGTEST_RANDOMX_EPOCH = 2048
REGTEST_RANDOMX_GENESIS_KEY = b"utocoin-regtest-randomx-genesis-key"


def regtest_randomx_seed_for_height(height, node=None, extra_blocks=None):
    """Compute the RandomX seed for a regtest block at the given height.

    Mirrors C++ ``GetRandomXKey``. Returns the seed as a hex string in Bitcoin
    display order (matches what the rx_seed RPC field returns).

    For heights >= ``REGTEST_RANDOMX_LAG + REGTEST_RANDOMX_EPOCH`` the helper
    needs the hash of an earlier block at ``key_height``. It will look it up in
    ``extra_blocks`` first (a {height: hex_hash} dict for blocks the test
    framework has built but not submitted yet), then fall back to ``node``.
    """
    if height < REGTEST_RANDOMX_LAG:
        return hashlib.sha256(REGTEST_RANDOMX_GENESIS_KEY).digest()[::-1].hex()
    key_height = ((height - REGTEST_RANDOMX_LAG) // REGTEST_RANDOMX_EPOCH) * REGTEST_RANDOMX_EPOCH
    if extra_blocks and key_height in extra_blocks:
        return extra_blocks[key_height]
    if node is None:
        raise ValueError(f"need node to look up rx_seed for height {height} (key_height={key_height})")
    return node.getblockhash(key_height)

# Match the cache size used by the C++ helper (see RandomXLightCache).
_CACHE_SLOTS = 2

_RANDOMX_FLAG_JIT = 8
_RANDOMX_FLAG_HARD_AES = 2


def _candidate_lib_paths():
    """Yield plausible librandomx.{so,dylib,dll} locations.

    The functional tests are typically run from the project root with the
    build directory at ./build, but we also honour an explicit override.
    """
    if os.environ.get("RANDOMX_LIB"):
        yield os.environ["RANDOMX_LIB"]

    sysname = platform.system()
    if sysname == "Darwin":
        names = ["librandomx.dylib"]
    elif sysname == "Windows":
        names = ["randomx.dll", "librandomx.dll"]
    else:
        names = ["librandomx.so"]

    here = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(here, "..", "..", ".."))
    search_dirs = [
        os.path.join(project_root, "build", "src", "randomx"),
        os.path.join(project_root, "build", "lib"),
        os.path.join(project_root, "build"),
        os.path.join(project_root, "src", "randomx"),
    ]
    for d in search_dirs:
        for name in names:
            yield os.path.join(d, name)


def _load_library():
    last_err = None
    for path in _candidate_lib_paths():
        if not os.path.exists(path):
            continue
        try:
            return ctypes.CDLL(path)
        except OSError as e:
            last_err = e
    msg = (
        "librandomx shared library not found. Build the `randomx_shared` target "
        "(produced by src/randomx/CMakeLists.txt) or set RANDOMX_LIB to its path."
    )
    if last_err is not None:
        msg += f" Last load error: {last_err}"
    raise RuntimeError(msg)


_lib = _load_library()

_lib.randomx_get_flags.restype = ctypes.c_int
_lib.randomx_get_flags.argtypes = []

_lib.randomx_alloc_cache.restype = ctypes.c_void_p
_lib.randomx_alloc_cache.argtypes = [ctypes.c_int]

_lib.randomx_init_cache.restype = None
_lib.randomx_init_cache.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]

_lib.randomx_release_cache.restype = None
_lib.randomx_release_cache.argtypes = [ctypes.c_void_p]

_lib.randomx_create_vm.restype = ctypes.c_void_p
_lib.randomx_create_vm.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

_lib.randomx_vm_set_cache.restype = None
_lib.randomx_vm_set_cache.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

_lib.randomx_destroy_vm.restype = None
_lib.randomx_destroy_vm.argtypes = [ctypes.c_void_p]

_lib.randomx_calculate_hash.restype = None
_lib.randomx_calculate_hash.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
]


# We omit JIT and HARD_AES on platforms where they have caused user reports of
# misbehaviour; the test framework cares about correctness, not throughput.
# Light mode is plenty fast for regtest-difficulty solves.
_FLAGS = _lib.randomx_get_flags()
# Disable FULL_MEM (dataset) — the lightcache path matches the C++ helper.
_FLAGS &= ~4  # RANDOMX_FLAG_FULL_MEM


class _Slot:
    __slots__ = ("key", "cache", "vm")

    def __init__(self):
        self.key = None
        self.cache = None
        self.vm = None


_lock = threading.Lock()
_slots = [_Slot() for _ in range(_CACHE_SLOTS)]
_next_replace = 0


def _get_vm_locked(key):
    """Return a VM initialized for `key`. Caller must hold `_lock`."""
    global _next_replace
    for slot in _slots:
        if slot.key == key:
            return slot.vm

    slot = _slots[_next_replace]
    _next_replace = (_next_replace + 1) % _CACHE_SLOTS

    if slot.cache is None:
        slot.cache = _lib.randomx_alloc_cache(_FLAGS)
        if not slot.cache:
            raise RuntimeError("randomx_alloc_cache failed")

    key_buf = ctypes.create_string_buffer(key, len(key))
    _lib.randomx_init_cache(slot.cache, key_buf, len(key))

    if slot.vm is None:
        slot.vm = _lib.randomx_create_vm(_FLAGS, slot.cache, None)
        if not slot.vm:
            raise RuntimeError("randomx_create_vm failed")
    else:
        _lib.randomx_vm_set_cache(slot.vm, slot.cache)

    slot.key = key
    return slot.vm


def randomx_hash(key, header):
    """Compute the RandomX hash of `header` keyed by `key`. Returns 32 bytes.

    Matches the C++ helper RandomXHash(key, input). The key is expected as
    32 bytes in uint256 storage order (little-endian). For convenience, a
    Bitcoin-style display hex string (big-endian visual, like the value
    returned by RPC) is also accepted and reversed internally to match C++.
    """
    if isinstance(key, str):
        # Bitcoin RPC returns hashes as big-endian display hex; uint256 stores
        # bytes in little-endian. Reverse so the bytes handed to RandomX match
        # the C++ side (which calls key.data() on a uint256).
        key = bytes.fromhex(key)[::-1]
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError(f"randomx key must be bytes-like, got {type(key).__name__}")
    if len(key) != RANDOMX_HASH_SIZE:
        raise ValueError(f"randomx key must be {RANDOMX_HASH_SIZE} bytes, got {len(key)}")
    if not isinstance(header, (bytes, bytearray, memoryview)):
        raise TypeError(f"randomx input must be bytes-like, got {type(header).__name__}")

    key = bytes(key)
    header = bytes(header)

    with _lock:
        vm = _get_vm_locked(key)
        out = (ctypes.c_ubyte * RANDOMX_HASH_SIZE)()
        _lib.randomx_calculate_hash(vm, header, len(header), out)
        return bytes(out)
