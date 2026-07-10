#pragma once

#include <array>
#include <cstddef>

enum class QueuePushResult {
    Inserted,
    Duplicate,
    Full,
};

template<typename T, std::size_t Capacity>
class BoundedUniqueQueue {
    static_assert(Capacity > 0, "Queue capacity must be positive");

public:
    QueuePushResult TryPush(const T& value) {
        for (std::size_t i = 0; i < size_; ++i) {
            if (queue_[(head_ + i) % Capacity] == value) {
                return QueuePushResult::Duplicate;
            }
        }
        if (size_ >= Capacity) {
            return QueuePushResult::Full;
        }

        queue_[(head_ + size_) % Capacity] = value;
        ++size_;
        return QueuePushResult::Inserted;
    }

    bool TryPop(T& value) {
        if (size_ == 0) {
            return false;
        }

        value = queue_[head_];
        head_ = (head_ + 1) % Capacity;
        --size_;
        return true;
    }

    void Clear() {
        head_ = 0;
        size_ = 0;
    }

    bool Empty() const {
        return size_ == 0;
    }

    std::size_t Size() const {
        return size_;
    }

private:
    std::array<T, Capacity> queue_{};
    std::size_t head_ = 0;
    std::size_t size_ = 0;
};
