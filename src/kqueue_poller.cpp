#include "peimon/event_loop.hpp"
#include <cerrno>
#include <cstring>
#include <sys/event.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace peimon {

class KqueuePoller : public IPoller {
public:
    KqueuePoller() : kq_(kqueue()) {
        if (kq_ < 0) {
            throw std::runtime_error(std::string("kqueue: ") + std::strerror(errno));
        }
    }

    ~KqueuePoller() override {
        if (kq_ >= 0) close(kq_);
    }

    void add(poll_fd_t fd, PollEvent events, void* user_data) override {
        struct kevent ev[2];
        int n = 0;
        if ((events & PollEvent::Read) != PollEvent::None) {
            EV_SET(&ev[n++], fd, EVFILT_READ, EV_ADD, 0, 0, user_data);
        }
        if ((events & PollEvent::Write) != PollEvent::None) {
            EV_SET(&ev[n++], fd, EVFILT_WRITE, EV_ADD, 0, 0, user_data);
        }
        if (n > 0 && kevent(kq_, ev, n, nullptr, 0, nullptr) < 0) {
            throw std::runtime_error(std::string("kevent ADD: ") + std::strerror(errno));
        }
    }

    void modify(poll_fd_t fd, PollEvent events, void* user_data) override {
        remove(fd);
        add(fd, events, user_data);
    }

    void remove(poll_fd_t fd) override {
        // Guard: avoid operating on invalid fd (e.g. -1); prevents use-after-close with reused fd.
        if (fd < 0 || kq_ < 0) return;
        struct kevent ev[2];
        EV_SET(&ev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        EV_SET(&ev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        // Ignore errors: fd may already be removed or closed; idempotent remove avoids double-close issues.
        (void)kevent(kq_, ev, 2, nullptr, 0, nullptr);
    }

    int wait(std::vector<FdEvent>& out_events, int timeout_ms) override {
        static constexpr std::size_t max_events = 64;
        struct kevent events[max_events];
        struct timespec ts;
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1'000'000;
        const struct timespec* timeout_ptr = (timeout_ms < 0) ? nullptr : &ts;
        int n = kevent(kq_, nullptr, 0, events, static_cast<int>(max_events), timeout_ptr);
        if (n < 0 && errno != EINTR) return -1;
        if (n <= 0) return n;
        out_events.clear();
        // Merge multiple events for the same fd (e.g. EVFILT_READ and EVFILT_WRITE) into one
        // so the callback is invoked only once. Double invocation would double-resume the
        // coroutine and cause undefined behavior / segfault.
        std::unordered_map<poll_fd_t, FdEvent> by_fd;
        for (int i = 0; i < n; ++i) {
            const poll_fd_t fd = static_cast<poll_fd_t>(events[i].ident);
            if (fd < 0) continue;  // Skip invalid ident (e.g. after close/reuse)
            PollEvent ev = PollEvent::None;
            if (events[i].filter == EVFILT_READ) ev = ev | PollEvent::Read;
            if (events[i].filter == EVFILT_WRITE) ev = ev | PollEvent::Write;
            if (events[i].flags & EV_ERROR) ev = ev | PollEvent::Error;
            auto it = by_fd.find(fd);
            if (it == by_fd.end()) {
                by_fd[fd] = FdEvent{fd, ev, events[i].udata};
            } else {
                it->second.events = it->second.events | ev;
            }
        }
        out_events.reserve(by_fd.size());
        for (auto& [fd, e] : by_fd) out_events.push_back(std::move(e));
        return static_cast<int>(out_events.size());
    }

private:
    int kq_{-1};
};

std::unique_ptr<IPoller> make_poller(void* /*wakeup_user_data*/) {
    return std::make_unique<KqueuePoller>();
}

}  // namespace peimon
