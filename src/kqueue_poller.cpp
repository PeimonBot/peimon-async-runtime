#include "peimon/event_loop.hpp"
#include <cerrno>
#include <cstring>
#include <sys/event.h>
#include <unistd.h>
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
        struct kevent ev[2];
        EV_SET(&ev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        EV_SET(&ev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        kevent(kq_, ev, 2, nullptr, 0, nullptr);
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
        out_events.reserve(static_cast<std::size_t>(n));
        for (int i = 0; i < n; ++i) {
            FdEvent e;
            e.fd = static_cast<poll_fd_t>(events[i].ident);
            e.events = PollEvent::None;
            if (events[i].filter == EVFILT_READ) e.events = e.events | PollEvent::Read;
            if (events[i].filter == EVFILT_WRITE) e.events = e.events | PollEvent::Write;
            if (events[i].flags & EV_ERROR) e.events = e.events | PollEvent::Error;
            e.user_data = events[i].udata;
            out_events.push_back(e);
        }
        return n;
    }

private:
    int kq_{-1};
};

std::unique_ptr<IPoller> make_poller(void* /*wakeup_user_data*/) {
    return std::make_unique<KqueuePoller>();
}

}  // namespace peimon
