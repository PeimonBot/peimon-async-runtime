#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <vector>

namespace peimon {

enum class PollEvent : std::uint32_t {
    None = 0,
    Read = 1 << 0,
    Write = 1 << 1,
    Error = 1 << 2,
};

inline PollEvent operator|(PollEvent a, PollEvent b) {
    return static_cast<PollEvent>(static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}

inline PollEvent operator&(PollEvent a, PollEvent b) {
    return static_cast<PollEvent>(static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b));
}

struct FdEvent {
    int fd{-1};
    PollEvent events{PollEvent::None};
    void* user_data{nullptr};
};

class IPoller {
public:
    virtual ~IPoller() = default;
    virtual void add(int fd, PollEvent events, void* user_data) = 0;
    virtual void modify(int fd, PollEvent events, void* user_data) = 0;
    virtual void remove(int fd) = 0;
    virtual int wait(std::vector<FdEvent>& out_events, int timeout_ms) = 0;
};

std::unique_ptr<IPoller> make_poller();

class EventLoop {
public:
    using Callback = std::function<void()>;

    EventLoop();
    ~EventLoop();

    EventLoop(const EventLoop&) = delete;
    EventLoop& operator=(const EventLoop&) = delete;

    void run();
    void stop();
    bool running() const { return running_; }

    void run_in_loop(Callback cb);
    void queue_in_loop(Callback cb);

    void register_fd(int fd, PollEvent events, void* user_data);
    void unregister_fd(int fd);
    void modify_fd(int fd, PollEvent events, void* user_data);

    template <class Rep, class Period>
    void run_after(std::chrono::duration<Rep, Period> delay, Callback cb);

private:
    void run_expired_timers();
    int next_timer_timeout_ms() const;

    void wakeup();
    void handle_wakeup();
    void do_pending_callbacks();

    std::unique_ptr<IPoller> poller_;
    bool running_{false};
    std::vector<Callback> pending_callbacks_;
    std::mutex pending_mutex_;
    int wakeup_fds_[2]{-1, -1};

    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    struct TimerEntry {
        TimePoint when;
        Callback cb;
        bool operator>(const TimerEntry& o) const { return when > o.when; }
    };
    std::priority_queue<TimerEntry, std::vector<TimerEntry>, std::greater<>> timer_queue_;
    mutable std::mutex timer_mutex_;
};

template <class Rep, class Period>
void EventLoop::run_after(std::chrono::duration<Rep, Period> delay, Callback cb) {
    if (!cb) return;
    auto when = Clock::now() + std::chrono::duration_cast<Clock::duration>(delay);
    {
        std::lock_guard lock(timer_mutex_);
        timer_queue_.push(TimerEntry{when, std::move(cb)});
    }
    wakeup();
}

}  // namespace peimon
