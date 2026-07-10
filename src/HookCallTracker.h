#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <mutex>

class HookCallTracker {
public:
    class Guard {
    public:
        explicit Guard(HookCallTracker& tracker) : tracker_(tracker) {
            tracker_.Enter();
        }

        ~Guard() {
            tracker_.Leave();
        }

        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;

    private:
        HookCallTracker& tracker_;
    };

    void WaitForIdle() {
        std::unique_lock<std::mutex> lock(waitMutex_);
        waiterPresent_.store(true, std::memory_order_release);
        idleCondition_.wait(lock, [this] {
            return activeCalls_.load(std::memory_order_acquire) == 0;
        });
        waiterPresent_.store(false, std::memory_order_release);
    }

private:
    void Enter() {
        activeCalls_.fetch_add(1, std::memory_order_acq_rel);
    }

    void Leave() {
        if (activeCalls_.fetch_sub(1, std::memory_order_acq_rel) == 1 &&
            waiterPresent_.load(std::memory_order_acquire)) {
            std::lock_guard<std::mutex> lock(waitMutex_);
            idleCondition_.notify_all();
        }
    }

    std::atomic<std::size_t> activeCalls_{0};
    std::atomic<bool> waiterPresent_{false};
    std::mutex waitMutex_;
    std::condition_variable idleCondition_;
};
