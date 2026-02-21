#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <vector>

namespace peimon {

/// Platform handle for pollable I/O: int on Unix, intptr_t on Windows (holds SOCKET).
#ifdef _WIN32
using poll_fd_t = intptr_t;
#else
using poll_fd_t = int;
#endif

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
    poll_fd_t fd{static_cast<poll_fd_t>(-1)};
    PollEvent events{PollEvent::None};
    void* user_data{nullptr};
};

class IPoller {
public:
    virtual ~IPoller() = default;
    virtual void add(poll_fd_t fd, PollEvent events, void* user_data) = 0;
    virtual void modify(poll_fd_t fd, PollEvent events, void* user_data) = 0;
    virtual void remove(poll_fd_t fd) = 0;
    virtual int wait(std::vector<FdEvent>& out_events, int timeout_ms) = 0;
    /// Wake the poller (e.g. from another thread). No-op on Unix (pipe used); posts to IOCP on Windows.
    virtual void wakeup() {}
};

/// On Windows, pass non-null \a wakeup_user_data so the poller can inject wakeup events (same as pipe on Unix).
std::unique_ptr<IPoller> make_poller(void* wakeup_user_data = nullptr);

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

    void register_fd(poll_fd_t fd, PollEvent events, void* user_data);
    void unregister_fd(poll_fd_t fd);
    void modify_fd(poll_fd_t fd, PollEvent events, void* user_data);

    template <class Rep, class Period>
    void run_after(std::chrono::duration<Rep, Period> delay, Callback cb);

private:
    void run_expired_timers();
    int next_timer_timeout_ms() const;
#if defined(__linux__)
    void update_timerfd();
#endif

    void wakeup();
    void handle_wakeup();
    void do_pending_callbacks();

    std::unique_ptr<IPoller> poller_;
    bool running_{false};
    std::vector<Callback> pending_callbacks_;
    std::mutex pending_mutex_;
    poll_fd_t wakeup_fds_[2]{static_cast<poll_fd_t>(-1), static_cast<poll_fd_t>(-1)};
#if defined(__linux__)
    poll_fd_t timerfd_{static_cast<poll_fd_t>(-1)};
#endif

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
#if defined(__linux__)
    if (timerfd_ >= 0) update_timerfd();
#endif
}

}  // namespace peimon
