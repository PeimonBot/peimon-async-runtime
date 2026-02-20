#include "peimon/event_loop.hpp"
#include "peimon/task.hpp"
#include <mutex>
#include <stdexcept>
#include <fstream>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif

namespace peimon {

namespace {

#ifndef _WIN32
int create_wakeup_pair(poll_fd_t fds[2]) {
#if defined(__linux__)
    int raw[2];
    if (pipe2(raw, O_CLOEXEC) != 0) return -1;
    fds[0] = raw[0];
    fds[1] = raw[1];
    return 0;
#else
    int raw[2];
    if (pipe(raw) != 0) return -1;
    for (int i = 0; i < 2; ++i) {
        int flags = fcntl(raw[i], F_GETFD);
        if (flags < 0 || fcntl(raw[i], F_SETFD, flags | FD_CLOEXEC) != 0) {
            close(raw[0]);
            close(raw[1]);
            return -1;
        }
    }
    fds[0] = raw[0];
    fds[1] = raw[1];
    return 0;
#endif
}
#endif

}  // namespace

EventLoop::EventLoop()
    : poller_(make_poller(
#ifdef _WIN32
          static_cast<void*>(this)
#else
          nullptr
#endif
              )) {
#ifndef _WIN32
    if (create_wakeup_pair(wakeup_fds_) < 0) {
        throw std::runtime_error("pipe for wakeup failed");
    }
    register_fd(wakeup_fds_[0], PollEvent::Read, this);
#endif
}

EventLoop::~EventLoop() {
#ifndef _WIN32
    unregister_fd(wakeup_fds_[0]);
    if (wakeup_fds_[0] >= 0) close(static_cast<int>(wakeup_fds_[0]));
    if (wakeup_fds_[1] >= 0) close(static_cast<int>(wakeup_fds_[1]));
#endif
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
            if (e.user_data == this &&
                (e.fd == wakeup_fds_[0] || e.fd == static_cast<poll_fd_t>(-1))) {
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

void EventLoop::register_fd(poll_fd_t fd, PollEvent events, void* user_data) {
    poller_->add(fd, events, user_data);
}

void EventLoop::unregister_fd(poll_fd_t fd) {
    poller_->remove(fd);
}

void EventLoop::modify_fd(poll_fd_t fd, PollEvent events, void* user_data) {
    poller_->modify(fd, events, user_data);
}

void EventLoop::wakeup() {
#ifdef _WIN32
    poller_->wakeup();
#else
    char c = 0;
    ::write(static_cast<int>(wakeup_fds_[1]), &c, 1);
#endif
}

void EventLoop::handle_wakeup() {
#ifndef _WIN32
    char buf[256];
    while (read(static_cast<int>(wakeup_fds_[0]), buf, sizeof(buf)) > 0)
        ;
#endif
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
