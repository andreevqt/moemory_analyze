#include "BoundedUniqueQueue.h"
#include "HookCallTracker.h"

#include <chrono>
#include <future>
#include <iostream>

namespace {
    bool TestBoundedQueueRejectsDuplicatesAndOverflow() {
        BoundedUniqueQueue<int, 2> queue;

        if (queue.TryPush(10) != QueuePushResult::Inserted ||
            queue.TryPush(10) != QueuePushResult::Duplicate ||
            queue.TryPush(20) != QueuePushResult::Inserted ||
            queue.TryPush(30) != QueuePushResult::Full) {
            return false;
        }

        int value = 0;
        return queue.TryPop(value) && value == 10 &&
               queue.TryPush(30) == QueuePushResult::Inserted &&
               queue.Size() == 2;
    }

    bool TestHookTrackerWaitsForActiveCall() {
        HookCallTracker tracker;
        std::promise<void> enteredPromise;
        std::shared_future<void> entered = enteredPromise.get_future().share();
        std::promise<void> releasePromise;
        std::shared_future<void> release = releasePromise.get_future().share();

        auto activeCall = std::async(std::launch::async, [&] {
            HookCallTracker::Guard guard(tracker);
            enteredPromise.set_value();
            release.wait();
        });
        entered.wait();

        auto waiter = std::async(std::launch::async, [&] {
            tracker.WaitForIdle();
        });
        if (waiter.wait_for(std::chrono::milliseconds(50)) != std::future_status::timeout) {
            releasePromise.set_value();
            activeCall.wait();
            return false;
        }

        releasePromise.set_value();
        if (waiter.wait_for(std::chrono::seconds(1)) != std::future_status::ready) {
            activeCall.wait();
            return false;
        }

        activeCall.get();
        waiter.get();
        return true;
    }
}

int main() {
    const bool queuePassed = TestBoundedQueueRejectsDuplicatesAndOverflow();
    const bool trackerPassed = TestHookTrackerWaitsForActiveCall();

    std::cout << (queuePassed ? "[+]" : "[-]")
              << " Bounded queue behavior.\n";
    std::cout << (trackerPassed ? "[+]" : "[-]")
              << " Hook call rundown behavior.\n";
    return queuePassed && trackerPassed ? 0 : 1;
}
