#pragma once

#include "peimon/event_loop.hpp"
#include <coroutine>
#include <cerrno>
#include <cstdint>
#include <memory>
#include <system_error>
#include <utility>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

namespace peimon {

/// Result of async_recv_from: bytes received and peer address.
struct UdpRecvResult {
    std::ptrdiff_t bytes{-1};  // <0 on error
    sockaddr_storage peer{};
    socklen_t peer_len{0};
};

/// UDP socket for QUIC/HTTP/3. Bind and use fd() with the event loop for reading.
/// Provides awaitables for async recv_from and send_to (C++23).
class UdpSocket {
public:
    UdpSocket() : fd_(static_cast<poll_fd_t>(-1)), loop_(nullptr) {}
    ~UdpSocket() { close(); }

    UdpSocket(UdpSocket&& other) noexcept
        : fd_(std::exchange(other.fd_, static_cast<poll_fd_t>(-1)))
        , loop_(std::exchange(other.loop_, nullptr)) {}
    UdpSocket& operator=(UdpSocket&& other) noexcept {
        if (this != &other) {
            close();
            fd_ = std::exchange(other.fd_, static_cast<poll_fd_t>(-1));
            loop_ = std::exchange(other.loop_, nullptr);
        }
        return *this;
    }
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    poll_fd_t fd() const { return fd_; }
    bool is_open() const { return fd_ != static_cast<poll_fd_t>(-1); }
    void set_event_loop(EventLoop* loop) { loop_ = loop; }

    void bind(const char* host, std::uint16_t port);
    void close();

    /// Receive one datagram. Returns number of bytes received, or <0 on error.
    std::ptrdiff_t recv_from(void* buf, std::size_t len, sockaddr* addr, socklen_t* addrlen);
    /// Send one datagram.
    std::ptrdiff_t send_to(const void* buf, std::size_t len, const sockaddr* addr, socklen_t addrlen);

    // Awaitables for use with co_await (C++20/23)
    class AsyncRecvFromAwaitable;
    class AsyncSendToAwaitable;

    AsyncRecvFromAwaitable async_recv_from(EventLoop& loop, void* buf, std::size_t len);
    AsyncSendToAwaitable async_send_to(EventLoop& loop, const void* buf, std::size_t len,
                                       const sockaddr* addr, socklen_t addrlen);

private:
    poll_fd_t fd_;
    EventLoop* loop_;
};

// --- AsyncRecvFromAwaitable ---
class UdpSocket::AsyncRecvFromAwaitable {
public:
    AsyncRecvFromAwaitable(UdpSocket& socket, EventLoop& loop, void* buf, std::size_t len)
        : socket_(&socket), loop_(&loop), buf_(buf), len_(len) {}

    bool await_ready() const noexcept { return !socket_ || !socket_->is_open() || len_ == 0; }

    void await_suspend(std::coroutine_handle<> h) {
        state_ = std::make_shared<State>();
        state_->handle = h;
        state_->loop = loop_;
        state_->fd = socket_->fd();
        state_->buf = buf_;
        state_->len = len_;
        state_->callback = [s = state_]() {
            s->loop->unregister_fd(s->fd);
#ifdef _WIN32
            int n = recvfrom(static_cast<SOCKET>(s->fd), static_cast<char*>(s->buf), static_cast<int>(s->len), 0,
                            reinterpret_cast<sockaddr*>(&s->peer), &s->peer_len);
            s->result.bytes = n;
#else
            ssize_t n = ::recvfrom(static_cast<int>(s->fd), s->buf, s->len, 0,
                                   reinterpret_cast<sockaddr*>(&s->peer), &s->peer_len);
            s->result.bytes = static_cast<std::ptrdiff_t>(n);
#endif
            if (s->result.bytes >= 0) {
                s->result.peer_len = s->peer_len;
                s->result.peer = s->peer;
            }
            s->handle.resume();
        };
        loop_->register_fd(socket_->fd(), PollEvent::Read, &state_->callback,
                          std::shared_ptr<void>(state_));
    }

    UdpRecvResult await_resume() {
        if (state_) return state_->result;
        return UdpRecvResult{};
    }

private:
    struct State {
        std::coroutine_handle<> handle;
        EventLoop* loop{nullptr};
        poll_fd_t fd{static_cast<poll_fd_t>(-1)};
        void* buf{nullptr};
        std::size_t len{0};
        sockaddr_storage peer{};
        socklen_t peer_len{sizeof(peer)};
        UdpRecvResult result;
        EventLoop::Callback callback;
    };
    UdpSocket* socket_;
    EventLoop* loop_;
    void* buf_;
    std::size_t len_;
    std::shared_ptr<State> state_;
};

inline UdpSocket::AsyncRecvFromAwaitable UdpSocket::async_recv_from(EventLoop& loop, void* buf, std::size_t len) {
    loop_ = &loop;
    return AsyncRecvFromAwaitable(*this, loop, buf, len);
}

// --- AsyncSendToAwaitable ---
class UdpSocket::AsyncSendToAwaitable {
public:
    AsyncSendToAwaitable(UdpSocket& socket, EventLoop& loop,
                         const void* buf, std::size_t len,
                         const sockaddr* addr, socklen_t addrlen)
        : socket_(&socket), loop_(&loop), buf_(buf), len_(len), addr_(addr), addrlen_(addrlen) {}

    bool await_ready() const noexcept { return !socket_ || !socket_->is_open() || len_ == 0; }

    void await_suspend(std::coroutine_handle<> h) {
        state_ = std::make_shared<State>();
        state_->handle = h;
        state_->loop = loop_;
        state_->fd = socket_->fd();
        state_->buf = buf_;
        state_->len = len_;
        state_->addr = addr_;
        state_->addrlen = addrlen_;
        state_->callback = [s = state_]() {
            s->loop->unregister_fd(s->fd);
#ifdef _WIN32
            int n = sendto(static_cast<SOCKET>(s->fd), static_cast<const char*>(s->buf), static_cast<int>(s->len), 0, s->addr, s->addrlen);
            s->result = n;
            if (n < 0) s->ec = std::error_code(WSAGetLastError(), std::system_category());
#else
            ssize_t n = ::sendto(static_cast<int>(s->fd), s->buf, s->len, 0, s->addr, s->addrlen);
            s->result = static_cast<std::ptrdiff_t>(n);
            if (n < 0) s->ec = std::error_code(errno, std::system_category());
#endif
            s->handle.resume();
        };
        loop_->register_fd(socket_->fd(), PollEvent::Write, &state_->callback,
                          std::shared_ptr<void>(state_));
    }

    std::ptrdiff_t await_resume() { return state_ ? state_->result : -1; }
    std::error_code error() const { return state_ ? state_->ec : std::error_code{}; }

private:
    struct State {
        std::coroutine_handle<> handle;
        EventLoop* loop{nullptr};
        poll_fd_t fd{static_cast<poll_fd_t>(-1)};
        const void* buf{nullptr};
        std::size_t len{0};
        const sockaddr* addr{nullptr};
        socklen_t addrlen{0};
        std::ptrdiff_t result{-1};
        std::error_code ec;
        EventLoop::Callback callback;
    };
    UdpSocket* socket_;
    EventLoop* loop_;
    const void* buf_;
    std::size_t len_;
    const sockaddr* addr_;
    socklen_t addrlen_;
    std::shared_ptr<State> state_;
};

inline UdpSocket::AsyncSendToAwaitable UdpSocket::async_send_to(EventLoop& loop,
                                                                const void* buf, std::size_t len,
                                                                const sockaddr* addr, socklen_t addrlen) {
    loop_ = &loop;
    return AsyncSendToAwaitable(*this, loop, buf, len, addr, addrlen);
}

}  // namespace peimon
