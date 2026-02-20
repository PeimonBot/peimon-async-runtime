#include "peimon/event_loop.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace peimon {

namespace {
struct WinsockInit {
    WinsockInit() {
        WSADATA d{};
        if (WSAStartup(MAKEWORD(2, 2), &d) != 0) std::terminate();
    }
    ~WinsockInit() { WSACleanup(); }
} g_winsock_init;
}  // namespace

namespace {

struct IocpSocketContext {
    poll_fd_t fd{static_cast<poll_fd_t>(-1)};
    void* user_data{nullptr};
    PollEvent events{PollEvent::None};
    OVERLAPPED read_ov{};
    OVERLAPPED write_ov{};
    std::vector<char> read_buf;
    bool read_pending{false};
    bool write_pending{false};
};

static char s_wakeup_sentinel;

static void start_read(IocpSocketContext* ctx, SOCKET s) {
    if (ctx->read_pending || (ctx->events & PollEvent::Read) == PollEvent::None) return;
    if (ctx->read_buf.empty()) ctx->read_buf.resize(256);
    WSABUF wbuf{static_cast<ULONG>(ctx->read_buf.size()), ctx->read_buf.data()};
    DWORD flags = 0;
    ctx->read_ov = OVERLAPPED{};
    if (WSARecv(s, &wbuf, 1, nullptr, &flags, &ctx->read_ov, nullptr) == 0 ||
        WSAGetLastError() == WSA_IO_PENDING) {
        ctx->read_pending = true;
    }
}

static void start_write(IocpSocketContext* ctx, SOCKET s) {
    if (ctx->write_pending || (ctx->events & PollEvent::Write) == PollEvent::None) return;
    ctx->write_ov = OVERLAPPED{};
    if (WSASend(s, nullptr, 0, nullptr, 0, &ctx->write_ov, nullptr) == 0 ||
        WSAGetLastError() == WSA_IO_PENDING) {
        ctx->write_pending = true;
    }
}

}  // namespace

class IocpPoller : public IPoller {
public:
    explicit IocpPoller(void* wakeup_user_data)
        : wakeup_user_data_(wakeup_user_data),
          iocp_(CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0)) {
        if (!iocp_) {
            throw std::runtime_error("CreateIoCompletionPort failed");
        }
    }

    ~IocpPoller() override {
        for (auto& [fd, ctx] : ctx_map_) {
            delete ctx;
        }
        if (iocp_) CloseHandle(iocp_);
    }

    void add(poll_fd_t fd, PollEvent events, void* user_data) override {
        auto* ctx = new IocpSocketContext{};
        ctx->fd = fd;
        ctx->user_data = user_data;
        ctx->events = events;
        ctx_map_[fd] = ctx;

        SOCKET s = static_cast<SOCKET>(fd);
        if (CreateIoCompletionPort(reinterpret_cast<HANDLE>(s), iocp_,
                                   reinterpret_cast<ULONG_PTR>(ctx), 0) == nullptr) {
            delete ctx;
            ctx_map_.erase(fd);
            throw std::runtime_error("CreateIoCompletionPort (associate socket) failed");
        }

        start_read(ctx, s);
        start_write(ctx, s);
    }

    void modify(poll_fd_t fd, PollEvent events, void* user_data) override {
        auto it = ctx_map_.find(fd);
        if (it == ctx_map_.end()) return;
        it->second->user_data = user_data;
        it->second->events = events;
        SOCKET s = static_cast<SOCKET>(fd);
        if (!it->second->read_pending) start_read(it->second, s);
        if (!it->second->write_pending) start_write(it->second, s);
    }

    void remove(poll_fd_t fd) override {
        auto it = ctx_map_.find(fd);
        if (it != ctx_map_.end()) {
            delete it->second;
            ctx_map_.erase(it);
        }
    }

    int wait(std::vector<FdEvent>& out_events, int timeout_ms) override {
        out_events.clear();
        DWORD t = (timeout_ms < 0) ? INFINITE : static_cast<DWORD>(timeout_ms);
        bool first = true;
        static constexpr std::size_t max_events = 64;

        while (out_events.size() < max_events) {
            DWORD bytes = 0;
            ULONG_PTR key = 0;
            LPOVERLAPPED ov = nullptr;
            DWORD wait_ms = first ? t : 0;
            first = false;

            if (!GetQueuedCompletionStatus(iocp_, &bytes, &key, &ov, wait_ms)) {
                if (ov == nullptr) {
                    DWORD err = GetLastError();
                    if (err == WAIT_TIMEOUT) return static_cast<int>(out_events.size());
                    if (err == ERROR_ABANDONED_WAIT_0) return -1;
                }
                break;
            }

            if (key == reinterpret_cast<ULONG_PTR>(&s_wakeup_sentinel)) {
                if (wakeup_user_data_) {
                    FdEvent e;
                    e.fd = static_cast<poll_fd_t>(-1);
                    e.events = PollEvent::Read;
                    e.user_data = wakeup_user_data_;
                    out_events.push_back(e);
                }
                return static_cast<int>(out_events.size());
            }

            auto* ctx = reinterpret_cast<IocpSocketContext*>(key);
            if (!ctx || ctx_map_.find(ctx->fd) == ctx_map_.end()) continue;

            SOCKET s = static_cast<SOCKET>(ctx->fd);
            if (ov == &ctx->read_ov) {
                ctx->read_pending = false;
                FdEvent e;
                e.fd = ctx->fd;
                e.events = PollEvent::Read;
                e.user_data = ctx->user_data;
                out_events.push_back(e);
                if ((ctx->events & PollEvent::Read) != PollEvent::None) start_read(ctx, s);
            } else if (ov == &ctx->write_ov) {
                ctx->write_pending = false;
                FdEvent e;
                e.fd = ctx->fd;
                e.events = PollEvent::Write;
                e.user_data = ctx->user_data;
                out_events.push_back(e);
                if ((ctx->events & PollEvent::Write) != PollEvent::None) start_write(ctx, s);
            }
        }
        return static_cast<int>(out_events.size());
    }

    void wakeup() override {
        if (iocp_) {
            PostQueuedCompletionStatus(iocp_, 0,
                                       reinterpret_cast<ULONG_PTR>(&s_wakeup_sentinel), nullptr);
        }
    }

private:
    void* wakeup_user_data_{nullptr};
    HANDLE iocp_{nullptr};
    std::unordered_map<poll_fd_t, IocpSocketContext*> ctx_map_;
};

std::unique_ptr<IPoller> make_poller(void* wakeup_user_data) {
    return std::make_unique<IocpPoller>(wakeup_user_data);
}

}  // namespace peimon
