#include "peimon/event_loop.hpp"
#include <atomic>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

namespace peimon {

namespace {

void ensure_winsock() {
    static const bool ok = []() {
        WSADATA d{};
        return WSAStartup(MAKEWORD(2, 2), &d) == 0;
    }();
    if (!ok) throw std::runtime_error("WSAStartup failed");
}

struct SocketContext {
    poll_fd_t fd{static_cast<poll_fd_t>(-1)};
    void* user_data{nullptr};
    PollEvent events{PollEvent::None};
    WSAEVENT event{WSA_INVALID_EVENT};
    ~SocketContext() {
        if (event != WSA_INVALID_EVENT) {
            WSACloseEvent(event);
            event = WSA_INVALID_EVENT;
        }
    }
};

constexpr DWORD to_completion_bits(PollEvent events) {
    return static_cast<DWORD>(static_cast<std::uint32_t>(events));
}

PollEvent from_completion_bits(DWORD bits) {
    return static_cast<PollEvent>(static_cast<std::uint32_t>(bits));
}

long to_network_event_mask(PollEvent events) {
    long mask = FD_CLOSE;
    if ((events & PollEvent::Read) != PollEvent::None) mask |= FD_READ | FD_ACCEPT;
    if ((events & PollEvent::Write) != PollEvent::None) mask |= FD_WRITE | FD_CONNECT;
    return mask;
}

PollEvent from_network_events(const WSANETWORKEVENTS& ne) {
    PollEvent events = PollEvent::None;
    if ((ne.lNetworkEvents & (FD_READ | FD_ACCEPT | FD_CLOSE)) != 0) {
        events = events | PollEvent::Read;
    }
    if ((ne.lNetworkEvents & (FD_WRITE | FD_CONNECT)) != 0) {
        events = events | PollEvent::Write;
    }
    // Only check error codes for events that actually occurred (MSDN: other elements not modified).
    const long occurred = ne.lNetworkEvents;
    if ((occurred & FD_READ) && ne.iErrorCode[FD_READ_BIT] != 0) events = events | PollEvent::Error;
    if ((occurred & FD_WRITE) && ne.iErrorCode[FD_WRITE_BIT] != 0) events = events | PollEvent::Error;
    if ((occurred & FD_OOB) && ne.iErrorCode[FD_OOB_BIT] != 0) events = events | PollEvent::Error;
    if ((occurred & FD_ACCEPT) && ne.iErrorCode[FD_ACCEPT_BIT] != 0) events = events | PollEvent::Error;
    if ((occurred & FD_CONNECT) && ne.iErrorCode[FD_CONNECT_BIT] != 0) events = events | PollEvent::Error;
    if ((occurred & FD_CLOSE) && ne.iErrorCode[FD_CLOSE_BIT] != 0) events = events | PollEvent::Error;
    return events;
}

char s_wakeup_key;
char s_stop_key;

}  // namespace

class IocpPoller : public IPoller {
public:
    explicit IocpPoller(void* wakeup_user_data)
        : wakeup_user_data_(wakeup_user_data),
          iocp_(CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0)),
          update_event_(WSACreateEvent()) {
        ensure_winsock();
        if (!iocp_) throw std::runtime_error("CreateIoCompletionPort failed");
        if (update_event_ == WSA_INVALID_EVENT) throw std::runtime_error("WSACreateEvent failed");
        bridge_thread_ = std::thread([this]() { bridge_events_to_iocp(); });
    }

    ~IocpPoller() override {
        stopping_.store(true, std::memory_order_release);
        WSASetEvent(update_event_);
        PostQueuedCompletionStatus(iocp_, 0, reinterpret_cast<ULONG_PTR>(&s_stop_key), nullptr);
        if (bridge_thread_.joinable()) bridge_thread_.join();

        std::lock_guard lock(ctx_mutex_);
        for (auto& [fd, ctx] : ctx_map_) {
            WSAEventSelect(static_cast<SOCKET>(fd), nullptr, 0);
            if (ctx->event != WSA_INVALID_EVENT) WSACloseEvent(ctx->event);
        }
        ctx_map_.clear();

        if (update_event_ != WSA_INVALID_EVENT) WSACloseEvent(update_event_);
        if (iocp_) CloseHandle(iocp_);
    }

    void add(poll_fd_t fd, PollEvent events, void* user_data) override {
        auto ctx = std::make_shared<SocketContext>();
        ctx->fd = fd;
        ctx->user_data = user_data;
        ctx->events = events;
        ctx->event = WSACreateEvent();
        if (ctx->event == WSA_INVALID_EVENT) throw std::runtime_error("WSACreateEvent failed");

        const SOCKET s = static_cast<SOCKET>(fd);
        if (WSAEventSelect(s, ctx->event, to_network_event_mask(events)) == SOCKET_ERROR) {
            WSACloseEvent(ctx->event);
            throw std::runtime_error("WSAEventSelect failed");
        }

        std::lock_guard lock(ctx_mutex_);
        if (ctx_map_.size() >= 63) {
            WSAEventSelect(s, nullptr, 0);
            WSACloseEvent(ctx->event);
            throw std::runtime_error("Windows poller currently supports up to 63 sockets");
        }
        ctx_map_[fd] = std::move(ctx);
        WSASetEvent(update_event_);
    }

    void modify(poll_fd_t fd, PollEvent events, void* user_data) override {
        std::lock_guard lock(ctx_mutex_);
        auto it = ctx_map_.find(fd);
        if (it == ctx_map_.end()) return;
        it->second->user_data = user_data;
        it->second->events = events;
        if (WSAEventSelect(static_cast<SOCKET>(fd), it->second->event, to_network_event_mask(events))
            == SOCKET_ERROR) {
            throw std::runtime_error("WSAEventSelect modify failed");
        }
        WSASetEvent(update_event_);
    }

    void remove(poll_fd_t fd) override {
        std::shared_ptr<SocketContext> removed;
        {
            std::lock_guard lock(ctx_mutex_);
            auto it = ctx_map_.find(fd);
            if (it == ctx_map_.end()) return;
            removed = it->second;
            ctx_map_.erase(it);
            WSASetEvent(update_event_);
        }
        WSAEventSelect(static_cast<SOCKET>(fd), nullptr, 0);
        // Do not WSACloseEvent here: bridge thread may still hold a copy of this context.
        // Event is closed in SocketContext destructor when last shared_ptr is released.
    }

    int wait(std::vector<FdEvent>& out_events, int timeout_ms) override {
        out_events.clear();
        constexpr std::size_t max_events = 64;
        const DWORD timeout = timeout_ms < 0 ? INFINITE : static_cast<DWORD>(timeout_ms);
        bool first_wait = true;

        while (out_events.size() < max_events) {
            DWORD bytes = 0;
            ULONG_PTR key = 0;
            LPOVERLAPPED ov = nullptr;
            const DWORD wait_ms = first_wait ? timeout : 0;
            first_wait = false;

            const BOOL ok = GetQueuedCompletionStatus(iocp_, &bytes, &key, &ov, wait_ms);
            if (!ok && ov == nullptr) {
                const DWORD err = GetLastError();
                if (err == WAIT_TIMEOUT) break;
                if (err == ERROR_ABANDONED_WAIT_0) return -1;
                continue;
            }

            if (key == reinterpret_cast<ULONG_PTR>(&s_wakeup_key)) {
                if (wakeup_user_data_) {
                    out_events.push_back(
                        FdEvent{static_cast<poll_fd_t>(-1), PollEvent::Read, wakeup_user_data_});
                }
                continue;
            }
            if (key == reinterpret_cast<ULONG_PTR>(&s_stop_key)) return -1;

            const poll_fd_t fd = static_cast<poll_fd_t>(key);
            void* user_data = nullptr;
            {
                std::lock_guard lock(ctx_mutex_);
                auto it = ctx_map_.find(fd);
                if (it == ctx_map_.end()) continue;
                user_data = it->second->user_data;
            }
            out_events.push_back(FdEvent{fd, from_completion_bits(bytes), user_data});
        }

        return static_cast<int>(out_events.size());
    }

    void wakeup() override {
        PostQueuedCompletionStatus(iocp_, 0, reinterpret_cast<ULONG_PTR>(&s_wakeup_key), nullptr);
    }

private:
    void bridge_events_to_iocp() {
        while (!stopping_.load(std::memory_order_acquire)) {
            std::vector<std::shared_ptr<SocketContext>> contexts;
            contexts.reserve(63);
            {
                std::lock_guard lock(ctx_mutex_);
                for (auto& [fd, ctx] : ctx_map_) {
                    contexts.push_back(ctx);
                    if (contexts.size() == 63) break;
                }
            }

            std::vector<WSAEVENT> events;
            events.reserve(contexts.size() + 1);
            events.push_back(update_event_);
            for (const auto& ctx : contexts) events.push_back(ctx->event);

            // Short timeout when sockets exist so new fds (e.g. accepted client) are picked up quickly.
            const DWORD timeout_ms = contexts.empty() ? 200 : 200;
            const DWORD rv = WSAWaitForMultipleEvents(
                static_cast<DWORD>(events.size()), events.data(), FALSE, timeout_ms, FALSE);

            if (rv == WSA_WAIT_TIMEOUT || rv == WSA_WAIT_FAILED) continue;

            const DWORD idx = rv - WSA_WAIT_EVENT_0;
            if (idx == 0) {
                WSAResetEvent(update_event_);
                continue;
            }
            if (idx >= events.size()) continue;

            const auto& ctx = contexts[idx - 1];
            WSANETWORKEVENTS ne{};
            if (WSAEnumNetworkEvents(static_cast<SOCKET>(ctx->fd), ctx->event, &ne) == SOCKET_ERROR) {
                continue;
            }

            const PollEvent translated = from_network_events(ne);
            if (translated == PollEvent::None) continue;
            PostQueuedCompletionStatus(iocp_, to_completion_bits(translated),
                                       static_cast<ULONG_PTR>(ctx->fd), nullptr);
        }
    }

    void* wakeup_user_data_{nullptr};
    HANDLE iocp_{nullptr};
    WSAEVENT update_event_{WSA_INVALID_EVENT};
    std::unordered_map<poll_fd_t, std::shared_ptr<SocketContext>> ctx_map_;
    std::mutex ctx_mutex_;
    std::thread bridge_thread_;
    std::atomic<bool> stopping_{false};
};

std::unique_ptr<IPoller> make_poller(void* wakeup_user_data) {
    return std::make_unique<IocpPoller>(wakeup_user_data);
}

}  // namespace peimon
