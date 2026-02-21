#include "peimon/event_loop.hpp"
#include "peimon/task.hpp"
#include <cerrno>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <fstream>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#include <fcntl.h>
#if defined(__linux__)
#include <sys/timerfd.h>
#include <poll.h>
#endif
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
    // Non-blocking read so handle_wakeup() never blocks when draining the pipe.
    int flags = fcntl(static_cast<int>(wakeup_fds_[0]), F_GETFL, 0);
    if (flags >= 0)
        fcntl(static_cast<int>(wakeup_fds_[0]), F_SETFL, flags | O_NONBLOCK);
    register_fd(wakeup_fds_[0], PollEvent::Read, this);
#if defined(__linux__)
    // timerfd disabled: some environments block in timerfd_create or epoll_wait never returns.
    // Timers are driven by the sleep-only path when timeout_ms < 1000.
    (void)timerfd_;
#endif
#endif
}

EventLoop::~EventLoop() {
#ifndef _WIN32
#if defined(__linux__)
    if (timerfd_ >= 0) {
        unregister_fd(static_cast<poll_fd_t>(timerfd_));
        close(static_cast<int>(timerfd_));
        timerfd_ = static_cast<poll_fd_t>(-1);
    }
#endif
    unregister_fd(wakeup_fds_[0]);
    if (wakeup_fds_[0] >= 0) close(static_cast<int>(wakeup_fds_[0]));
    if (wakeup_fds_[1] >= 0) close(static_cast<int>(wakeup_fds_[1]));
#endif
}

void EventLoop::run() {
    running_ = true;
    set_event_loop(this);
    do_pending_callbacks();  // run initial tasks (e.g. server bind/listen) before first wait
#if defined(__linux__)
    if (timerfd_ >= 0) update_timerfd();
#endif
    std::vector<FdEvent> events;
    while (running_) {
        int timeout_ms = next_timer_timeout_ms();
#ifndef _WIN32
        // When we have pending timers with short delay, use a 0ms (non-blocking) wait
        // so we always service I/O and wakeup; timers are driven by run_expired_timers().
        // This avoids both skipping wait() (which starves TCP/UDP) and long waits that
        // never return in some CI environments.
        if (timeout_ms > 0 && timeout_ms < 1000) {
            timeout_ms = 0;
        }
#endif
#if defined(__linux__)
        if (timerfd_ >= 0) {
            timeout_ms = (std::min)(timeout_ms, 1000);
        }
#endif
        int n = poller_->wait(events, timeout_ms);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
#ifndef _WIN32
        // After a non-blocking wait with no events, yield time so timers can expire.
        if (timeout_ms == 0 && n == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
#endif
        for (const auto& e : events) {
            if (e.user_data == this &&
                (e.fd == wakeup_fds_[0] || e.fd == static_cast<poll_fd_t>(-1))) {
                handle_wakeup();
            }
#if defined(__linux__)
            else if (timerfd_ >= 0 && e.fd == static_cast<poll_fd_t>(timerfd_)) {
                uint64_t expirations = 0;
                while (read(static_cast<int>(timerfd_), &expirations, sizeof(expirations)) == sizeof(expirations) && expirations > 0)
                    ;
                run_expired_timers();
                update_timerfd();
            }
#endif
            else if (e.user_data) {
                std::shared_ptr<void> keep;
                auto it = fd_keep_alive_.find(e.fd);
                if (it != fd_keep_alive_.end()) keep = it->second;
                // Only invoke callback if fd is still registered (keep exists). Otherwise the
                // event may be stale (e.g. kqueue returned an event for an fd that was already
                // removed), and user_data could point to freed memory → segfault on macOS.
                if (!keep) continue;
                auto* cb = static_cast<Callback*>(e.user_data);
                (*cb)();
            }
        }
        run_expired_timers();
#if defined(__linux__)
        if (timerfd_ >= 0) update_timerfd();
#endif
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

void EventLoop::register_fd(poll_fd_t fd, PollEvent events, void* user_data,
                            std::shared_ptr<void> keep_alive) {
    if (keep_alive) fd_keep_alive_[fd] = keep_alive;
    poller_->add(fd, events, user_data);
}

void EventLoop::unregister_fd(poll_fd_t fd) {
    fd_keep_alive_.erase(fd);
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
    // Drain wakeup pipe so epoll/kqueue stops reporting read; non-blocking so we never block.
    char buf[256];
    ssize_t n;
    while (true) {
        n = read(static_cast<int>(wakeup_fds_[0]), buf, sizeof(buf));
        if (n > 0) continue;
        if (n < 0 && errno == EINTR) continue;
        break;  // 0 (EOF) or EAGAIN/EWOULDBLOCK when drained
    }
    (void)n;
#else
    // Windows: wakeup is signaled via IOCP (PostQueuedCompletionStatus); nothing to drain here.
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
    return static_cast<int>((std::min)(d.count(), std::int64_t(1000)));
}

#ifndef _WIN32
#if defined(__linux__)
void EventLoop::update_timerfd() {
    if (timerfd_ < 0) return;
    std::lock_guard lock(timer_mutex_);
    if (timer_queue_.empty()) {
        struct itimerspec spec {};
        timerfd_settime(static_cast<int>(timerfd_), 0, &spec, nullptr);
        return;
    }
    auto next = timer_queue_.top().when;
    auto now = Clock::now();
    if (next <= now) {
        struct itimerspec spec {};
        spec.it_value.tv_sec = 0;
        spec.it_value.tv_nsec = 1;
        timerfd_settime(static_cast<int>(timerfd_), 0, &spec, nullptr);
        return;
    }
    auto d = next - now;
    auto sec = std::chrono::duration_cast<std::chrono::seconds>(d);
    auto nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(d - sec);
    struct itimerspec spec {};
    spec.it_value.tv_sec = sec.count();
    spec.it_value.tv_nsec = static_cast<long>(nsec.count());
    if (spec.it_value.tv_nsec >= 1000000000) {
        spec.it_value.tv_sec += 1;
        spec.it_value.tv_nsec -= 1000000000;
    }
    timerfd_settime(static_cast<int>(timerfd_), 0, &spec, nullptr);
}
#endif
#endif

}  // namespace peimon
