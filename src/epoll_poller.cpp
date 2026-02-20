#include "peimon/event_loop.hpp"
#include <cerrno>
#include <cstring>
#include <unordered_map>
#include <sys/epoll.h>
#include <unistd.h>

namespace peimon {

struct FdContext {
    poll_fd_t fd;
    void* user_data;
};

class EpollPoller : public IPoller {
public:
    EpollPoller() : epfd_(epoll_create1(EPOLL_CLOEXEC)) {
        if (epfd_ < 0) {
            throw std::runtime_error(std::string("epoll_create1: ") + std::strerror(errno));
        }
    }

    ~EpollPoller() override {
        for (auto& [fd, ctx] : fd_ctx_) delete ctx;
        if (epfd_ >= 0) close(epfd_);
    }

    void add(poll_fd_t fd, PollEvent events, void* user_data) override {
        auto* ctx = new FdContext{fd, user_data};
        fd_ctx_[fd] = ctx;
        epoll_event ev{};
        ev.events = to_epoll_events(events);
        ev.data.ptr = ctx;
        if (epoll_ctl(epfd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
            delete ctx;
            fd_ctx_.erase(fd);
            throw std::runtime_error(std::string("epoll_ctl ADD: ") + std::strerror(errno));
        }
    }

    void modify(poll_fd_t fd, PollEvent events, void* user_data) override {
        auto it = fd_ctx_.find(fd);
        if (it == fd_ctx_.end()) return;
        it->second->user_data = user_data;
        epoll_event ev{};
        ev.events = to_epoll_events(events);
        ev.data.ptr = it->second;
        epoll_ctl(epfd_, EPOLL_CTL_MOD, fd, &ev);
    }

    void remove(poll_fd_t fd) override {
        auto it = fd_ctx_.find(fd);
        if (it != fd_ctx_.end()) {
            epoll_ctl(epfd_, EPOLL_CTL_DEL, fd, nullptr);
            delete it->second;
            fd_ctx_.erase(it);
        }
    }

    int wait(std::vector<FdEvent>& out_events, int timeout_ms) override {
        static constexpr std::size_t max_events = 64;
        epoll_event events[max_events];
        int n = epoll_wait(epfd_, events, static_cast<int>(max_events), timeout_ms);
        if (n < 0 && errno != EINTR) return -1;
        if (n <= 0) return n;
        out_events.clear();
        out_events.reserve(static_cast<std::size_t>(n));
        for (int i = 0; i < n; ++i) {
            auto* ctx = static_cast<FdContext*>(events[i].data.ptr);
            FdEvent e;
            e.fd = ctx->fd;
            e.events = from_epoll_events(events[i].events);
            e.user_data = ctx->user_data;
            out_events.push_back(e);
        }
        return n;
    }

private:
    static std::uint32_t to_epoll_events(PollEvent e) {
        std::uint32_t r = 0;
        if ((e & PollEvent::Read) != PollEvent::None) r |= EPOLLIN;
        if ((e & PollEvent::Write) != PollEvent::None) r |= EPOLLOUT;
        if ((e & PollEvent::Error) != PollEvent::None) r |= EPOLLERR;
        return r;
    }

    static PollEvent from_epoll_events(std::uint32_t e) {
        PollEvent r = PollEvent::None;
        if (e & EPOLLIN) r = r | PollEvent::Read;
        if (e & EPOLLOUT) r = r | PollEvent::Write;
        if (e & EPOLLERR) r = r | PollEvent::Error;
        return r;
    }

    int epfd_{-1};
    std::unordered_map<poll_fd_t, FdContext*> fd_ctx_;
};

std::unique_ptr<IPoller> make_poller(void* /*wakeup_user_data*/) {
    return std::make_unique<EpollPoller>();
}

}  // namespace peimon
