#include "peimon/event_loop.hpp"
#include "peimon/task.hpp"
#include <mutex>
#include <stdexcept>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>

namespace peimon {

namespace {

int create_wakeup_pair(int fds[2]) {
    return pipe2(fds, O_CLOEXEC);
}

}  // namespace

EventLoop::EventLoop() : poller_(make_poller()) {
    if (create_wakeup_pair(wakeup_fds_) < 0) {
        throw std::runtime_error("pipe for wakeup failed");
    }
    register_fd(wakeup_fds_[0], PollEvent::Read, this);
}

EventLoop::~EventLoop() {
    unregister_fd(wakeup_fds_[0]);
    if (wakeup_fds_[0] >= 0) close(wakeup_fds_[0]);
    if (wakeup_fds_[1] >= 0) close(wakeup_fds_[1]);
}

void EventLoop::run() {
    running_ = true;
    set_event_loop(this);
    do_pending_callbacks();  // run initial tasks (e.g. server bind/listen) before first wait
    std::vector<FdEvent> events;
    int iter = 0;
    while (running_) {
        int timeout_ms = next_timer_timeout_ms();
        int n = poller_->wait(events, timeout_ms);
        ++iter;
        if (n < 0) break;
        for (const auto& e : events) {
            if (e.user_data == this && e.fd == wakeup_fds_[0]) {
                handle_wakeup();
            } else if (e.user_data) {
                auto* cb = static_cast<Callback*>(e.user_data);
                (*cb)();
            }
        }
        run_expired_timers();
        do_pending_callbacks();
    }
    set_event_loop(nullptr);
}

void EventLoop::stop() {
    running_ = false;
    wakeup();
}

void EventLoop::run_in_loop(Callback cb) {
    if (cb) {
        std::lock_guard lock(pending_mutex_);
        pending_callbacks_.push_back(std::move(cb));
    }
    wakeup();
}

void EventLoop::queue_in_loop(Callback cb) {
    run_in_loop(std::move(cb));
}

void EventLoop::register_fd(int fd, PollEvent events, void* user_data) {
    poller_->add(fd, events, user_data);
}

void EventLoop::unregister_fd(int fd) {
    poller_->remove(fd);
}

void EventLoop::modify_fd(int fd, PollEvent events, void* user_data) {
    poller_->modify(fd, events, user_data);
}

void EventLoop::wakeup() {
    char c = 0;
    ::write(wakeup_fds_[1], &c, 1);
}

void EventLoop::handle_wakeup() {
    char buf[256];
    while (read(wakeup_fds_[0], buf, sizeof(buf)) > 0)
        ;
}

void EventLoop::do_pending_callbacks() {
    std::vector<Callback> swap;
    {
        std::lock_guard lock(pending_mutex_);
        swap.swap(pending_callbacks_);
    }
    for (auto& cb : swap) {
        if (cb) cb();
    }
}

void EventLoop::run_expired_timers() {
    const auto now = Clock::now();
    std::vector<Callback> expired;
    {
        std::lock_guard lock(timer_mutex_);
        while (!timer_queue_.empty() && timer_queue_.top().when <= now) {
            expired.push_back(std::move(timer_queue_.top().cb));
            timer_queue_.pop();
        }
    }
    for (auto& cb : expired) {
        if (cb) cb();
    }
}

int EventLoop::next_timer_timeout_ms() const {
    std::lock_guard lock(timer_mutex_);
    if (timer_queue_.empty()) return 1000;
    auto now = Clock::now();
    auto next = timer_queue_.top().when;
    if (next <= now) return 0;
    auto d = std::chrono::duration_cast<std::chrono::milliseconds>(next - now);
    return static_cast<int>(std::min(d.count(), std::int64_t(1000)));
}

}  // namespace peimon
