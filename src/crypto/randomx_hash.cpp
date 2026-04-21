// Copyright (c) 2026 The Utocoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/randomx_hash.h>

#include <randomx.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <stdexcept>

namespace {

class RandomXLightCache
{
public:
    RandomXLightCache()
        : m_flags{randomx_get_flags()}
    {
    }

    ~RandomXLightCache()
    {
        for (Entry& entry : m_entries) {
            if (entry.vm != nullptr) {
                randomx_destroy_vm(entry.vm);
            }
            if (entry.cache != nullptr) {
                randomx_release_cache(entry.cache);
            }
        }
    }

    uint256 Hash(Span<const unsigned char> key, Span<const unsigned char> input)
    {
        if (key.size() != uint256::size()) {
            throw std::runtime_error("RandomX key must be 32 bytes");
        }

        std::lock_guard<std::mutex> lock{m_mutex};
        Entry& entry = GetEntry(key);
        uint256 hash;
        randomx_calculate_hash(entry.vm, input.data(), input.size(), hash.begin());
        return hash;
    }

private:
    struct Entry {
        bool occupied{false};
        std::array<unsigned char, uint256::size()> key{};
        randomx_cache* cache{nullptr};
        randomx_vm* vm{nullptr};
    };

    Entry& GetEntry(Span<const unsigned char> key)
    {
        for (Entry& entry : m_entries) {
            if (entry.occupied && std::memcmp(entry.key.data(), key.data(), key.size()) == 0) {
                return entry;
            }
        }

        Entry& entry = m_entries[m_next_replace];
        m_next_replace = (m_next_replace + 1) % m_entries.size();

        if (entry.cache == nullptr) {
            entry.cache = randomx_alloc_cache(m_flags);
            if (entry.cache == nullptr) {
                throw std::runtime_error("Failed to allocate RandomX cache");
            }
        }

        std::memcpy(entry.key.data(), key.data(), key.size());
        randomx_init_cache(entry.cache, entry.key.data(), entry.key.size());

        if (entry.vm == nullptr) {
            entry.vm = randomx_create_vm(m_flags, entry.cache, nullptr);
            if (entry.vm == nullptr) {
                throw std::runtime_error("Failed to create RandomX VM");
            }
        } else {
            randomx_vm_set_cache(entry.vm, entry.cache);
        }

        entry.occupied = true;
        return entry;
    }

    randomx_flags m_flags;
    std::mutex m_mutex;
    std::array<Entry, 2> m_entries{};
    size_t m_next_replace{0};
};

RandomXLightCache& GetRandomXLightCache()
{
    static RandomXLightCache cache;
    return cache;
}

} // namespace

uint256 RandomXHash(Span<const unsigned char> key, Span<const unsigned char> input)
{
    return GetRandomXLightCache().Hash(key, input);
}
