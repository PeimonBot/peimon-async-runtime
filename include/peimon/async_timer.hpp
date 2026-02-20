#pragma once
// Timer and sleep_for awaitables using EventLoop's timer queue (epoll timeout + run_expired_timers).
// C++20/23 compatible.

#include "peimon/event_loop.hpp"
#include "peimon/task.hpp"
#include <chrono>
#include <coroutine>

namespace peimon {

/// One-shot timer abstraction using the EventLoop's timer queue (epoll timeout +
/// run_expired_timers). Awaitable; suspends the coroutine until the delay has elapsed.
class Timer {
public:
    template <class Rep, class Period>
    explicit Timer(EventLoop& loop, std::chrono::duration<Rep, Period> delay)
        : loop_(&loop)
        , delay_ms_(std::chrono::duration_cast<std::chrono::milliseconds>(delay).count()) {}

    bool await_ready() const noexcept { return delay_ms_ <= 0; }

    void await_suspend(std::coroutine_handle<> h) {
        auto handle = h;
        loop_->run_after(std::chrono::milliseconds(delay_ms_), [handle]() mutable { handle.resume(); });
    }

    void await_resume() noexcept {}

private:
    EventLoop* loop_;
    long delay_ms_;
};

/// Awaitable that suspends the current coroutine for the given duration.
/// Implemented via Timer; uses the EventLoop's timer facility to wake the coroutine.
template <class Rep, class Period>
inline Timer sleep_for(EventLoop& loop, std::chrono::duration<Rep, Period> delay) {
    return Timer(loop, delay);
}

}  // namespace peimon
