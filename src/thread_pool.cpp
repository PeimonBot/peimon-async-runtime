#include "peimon/thread_pool.hpp"
#include <thread>

namespace peimon {

ThreadPoolExecutor::ThreadPoolExecutor(std::size_t num_threads) {
    num_threads = (num_threads > 0) ? num_threads : 1;
    workers_.reserve(num_threads);
    for (std::size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back(&ThreadPoolExecutor::worker_loop, this);
    }
}

ThreadPoolExecutor::~ThreadPoolExecutor() {
    shutdown();
}

void ThreadPoolExecutor::submit(Task task) {
    if (!task) return;
    {
        std::lock_guard lock(mutex_);
        if (shutdown_) return;
        queue_.push(std::move(task));
    }
    cv_.notify_one();
}

void ThreadPoolExecutor::shutdown() {
    {
        std::lock_guard lock(mutex_);
        shutdown_ = true;
    }
    cv_.notify_all();
    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }
}

void ThreadPoolExecutor::worker_loop() {
    for (;;) {
        Task task;
        {
            std::unique_lock lock(mutex_);
            cv_.wait(lock, [this] { return shutdown_ || !queue_.empty(); });
            if (shutdown_ && queue_.empty()) return;
            if (!queue_.empty()) {
                task = std::move(queue_.front());
                queue_.pop();
            }
        }
        if (task) task();
    }
}

}  // namespace peimon
