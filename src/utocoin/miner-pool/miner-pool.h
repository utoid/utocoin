#ifndef __UTOCOIN_MINER_POOL_H__
#define __UTOCOIN_MINER_POOL_H__

#include <pow.h>
#include <vector>
#include <thread>
#include <random>
#include <valarray>

namespace utocoin {

namespace {
template<bool T>
class FreeGuard {
protected:
    static constexpr bool isAdd = T;
    std::atomic<uint32_t> &m_nVar;
    std::condition_variable &cv;
public:
    FreeGuard(std::atomic<uint32_t> &var, std::condition_variable &cv) : m_nVar(var), cv(cv) {
        isAdd ? m_nVar.fetch_add(1, std::memory_order_release) : m_nVar.fetch_sub(1, std::memory_order_release);
        cv.notify_all();
    }
    ~FreeGuard() {
        isAdd ? m_nVar.fetch_sub(1, std::memory_order_release) : m_nVar.fetch_add(1, std::memory_order_release);
        cv.notify_all();
    }
};
}

class Log
{
protected:
    inline static std::mutex lock;
    std::lock_guard<std::mutex> guard;
    std::ostream &output;

    using Manip = std::ostream& (*)(std::ostream&);
public:

    static std::string Now()
    {
        using namespace std::chrono;
        auto tp = system_clock::now();
        auto t = system_clock::to_time_t(tp);
        auto ms = duration_cast<milliseconds>(tp.time_since_epoch()) % 1000;

        std::tm tm;
        localtime_r(&t, &tm);

        std::ostringstream ss;
        ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
           << "." << std::setw(3) << std::setfill('0') << ms.count();
        return ss.str();
    }

    Log(std::ostream &o = std::cout) : guard(lock), output(o)
    {
        output << "[" << Now() << "] ";
    }

    template<typename T>
    Log& operator<<(const T& v)
    {
        output << v;
        return *this;
    }

    Log& operator<<(Manip manip)
    {
        manip(output);
        return *this;
    }
};

class CMinerPool {
protected:
    const uint32_t m_nThreads;
    const Consensus::Params& params;

    std::vector<std::thread> m_vecWorkds;

    std::atomic<bool> m_bStop{false};
    std::atomic<uint32_t> m_nHashCount{0};
    std::atomic<uint32_t> m_nTaskEpoch{0};
    std::atomic<uint32_t> m_nDoneEpoch{0};
    std::atomic<uint32_t> m_nFreeWorkers{0};
    std::atomic<uint32_t> m_nNonce{0};
    std::atomic<uint32_t> m_nSuccessMiner{0};

    bool m_bFound{false};
    std::mutex mtx;
    std::mutex mining_lock;
    std::condition_variable cv;

    std::shared_ptr<const CBlock> m_pSharedBlock;
public:
    explicit CMinerPool(uint32_t threads, const Consensus::Params& params) : m_nThreads(threads), params(params) {
        std::cout.setf(std::ios::unitbuf);
        for ( uint32_t i = 0;i < m_nThreads;i++ ) {
            m_vecWorkds.emplace_back([this, i] {
                compute_thread(i);
            });
        }
    }

    void do_working(uint32_t thread_idx) {
        FreeGuard<false> guard(m_nFreeWorkers, cv);

        uint32_t mRangePerThread = std::numeric_limits<uint32_t>::max() / m_nThreads;
        uint32_t begin = mRangePerThread * thread_idx;
        uint32_t end = mRangePerThread * (thread_idx + 1);

        CBlock block = *m_pSharedBlock;

        uint32_t nWorkingEpoch = m_nTaskEpoch.load(std::memory_order_acquire);
        uint32_t nCurrentDoneEpoch = m_nDoneEpoch.load(std::memory_order_acquire);
        Log() << nWorkingEpoch << ", " << nCurrentDoneEpoch << std::endl;

        std::string threadHeader = std::format("Thread[{}][{},{})[{},{}] -- ", thread_idx, begin, end, nWorkingEpoch, nCurrentDoneEpoch);
        Log() << threadHeader << "begin compute" << std::endl;

        for ( uint32_t i = begin;i < end; block.nNonce = i++ ) {
            if ( m_nDoneEpoch.load(std::memory_order_acquire) == nWorkingEpoch || m_bStop.load(std::memory_order_acquire)) {
                if ( m_bStop.load(std::memory_order_acquire) ) {
                    Log() << threadHeader << "got stop signal" << std::endl;
                } else {
                    Log() << threadHeader << "task completed by other thread"<< std::endl;
                }
                break;
            }

            m_nHashCount.fetch_add(1);
            // thread_local std::mt19937 rng{ []{
            //     std::random_device rd;
            //     return std::mt19937(rd());
            // }() };
            //
            // std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);
            // uint32_t r = dist(rng);
            //
            // if (r % 10000 == 0) {
            //     sleep(r / 10000 % 10);
            if ( CheckProofOfWork(block.GetPowHash(params), block.nBits, params) ) {
                // found
                if ( m_nDoneEpoch.compare_exchange_strong(nCurrentDoneEpoch, nWorkingEpoch, std::memory_order_release, std::memory_order_relaxed) ) {
                    Log() << threadHeader << "finish work, found nonce " << block.nNonce << std::endl;
                    m_bFound = true;
                    m_nNonce.store(block.nNonce, std::memory_order_relaxed);
                    m_nSuccessMiner.store(thread_idx, std::memory_order_relaxed);
                    cv.notify_all();
                } else {
                    Log() << threadHeader << "other worker finished, ignore this nonce" << std::endl;
                }
                break;
            }
        }
    }

    void compute_thread(uint32_t thread_idx) {
        FreeGuard<true> guard(m_nFreeWorkers, cv);
        for ( ;; ) {
            uint32_t workingEpoch = m_nTaskEpoch.load(std::memory_order_acquire);

            {
                std::unique_lock<std::mutex> lock(mtx);
                cv.wait(lock, [&] {
                    return workingEpoch != m_nTaskEpoch.load(std::memory_order_acquire) || m_bStop.load(std::memory_order_acquire);
                });
                lock.unlock();
            }

            Log() << "start working " << thread_idx << std::endl;

            if ( m_bStop.load(std::memory_order_acquire) ) {
                break;
            }
            do_working(thread_idx);
            Log() << "working finished" << std::endl;
        }
        Log() << "thread " << thread_idx << " finished" << std::endl;
    }

    ~CMinerPool() {
        Stop();
    }

    void Stop() {
        m_bStop.store(true, std::memory_order_release);
        cv.notify_all();
    }

    uint32_t Mining(std::shared_ptr<CBlock> block)
    {
        std::lock_guard<std::mutex> lk(mining_lock);

        m_pSharedBlock = block;
        m_bFound = false;

        m_nTaskEpoch.fetch_add(1);
        m_nHashCount.store(0, std::memory_order_relaxed);
        uint32_t workingEpoch = m_nTaskEpoch.load(std::memory_order_acquire);

        Log() << "------ begin to mining epoch [" << workingEpoch << "] -----" << std::endl;
        cv.notify_all();
        return workingEpoch;
    }

    std::optional<uint32_t> Wait(uint32_t workingEpoch, uint32_t *pThreadIndex = nullptr)
    {
        using clock = std::chrono::steady_clock;

        auto last_time = clock::now();
        uint64_t last_hash = 0;

        std::unique_lock<std::mutex> lock(mtx);
        for (;;) {
            bool finished = cv.wait_for(lock, std::chrono::seconds(10), [&]{
                return m_nFreeWorkers.load(std::memory_order_acquire) == m_nThreads && m_nDoneEpoch.load(std::memory_order_acquire) == workingEpoch;
            });
            if ( finished ) {
                break;
            }

            auto now = clock::now();
            auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_time).count();

            if (dt > 0) {
                uint64_t cur = m_nHashCount.load(std::memory_order::relaxed);
                uint64_t delta = cur - last_hash;

                double hash_per_sec = (double)delta * 1000.0 / (double)dt;

                Log() << "---------- total hash[epoch:" << workingEpoch << "]: " << cur
                      << " | +" << delta
                      << " | " << hash_per_sec << " H/s\n";

                last_hash = cur;
                last_time = now;
            }
        }


        if ( m_bFound ) {
            if ( pThreadIndex ) {
                *pThreadIndex = m_nSuccessMiner.load();
            }
            return std::make_optional(m_nNonce.load());
        } else {
            return std::optional<uint32_t>{};
        }
    }
};

}

#endif