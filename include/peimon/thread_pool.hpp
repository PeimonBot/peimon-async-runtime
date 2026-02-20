#pragma once

#include <cstddef>
#include <functional>
#include <queue>
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>

namespace peimon {

class ThreadPoolExecutor {
public:
    using Task = std::function<void()>;

    explicit ThreadPoolExecutor(std::size_t num_threads);
    ~ThreadPoolExecutor();

    ThreadPoolExecutor(const ThreadPoolExecutor&) = delete;
    ThreadPoolExecutor& operator=(const ThreadPoolExecutor&) = delete;

    void submit(Task task);
    void shutdown();
    std::size_t num_threads() const { return workers_.size(); }

private:
    void worker_loop();

    std::vector<std::thread> workers_;
    std::queue<Task> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool shutdown_{false};
};

}  // namespace peimon
