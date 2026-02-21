#pragma once

#include "peimon/event_loop.hpp"
#include "peimon/task.hpp"
#include <coroutine>
#include <cstring>
#include <memory>
#include <optional>
#include <system_error>
#include <cerrno>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace peimon {

class TcpSocket {
public:
    TcpSocket() : fd_(static_cast<poll_fd_t>(-1)), loop_(nullptr) {}
    explicit TcpSocket(poll_fd_t fd, EventLoop* loop = nullptr) : fd_(fd), loop_(loop) {}

    TcpSocket(TcpSocket&& other) noexcept
        : fd_(std::exchange(other.fd_, static_cast<poll_fd_t>(-1)))
        , loop_(std::exchange(other.loop_, nullptr)) {}

    TcpSocket& operator=(TcpSocket&& other) noexcept {
        if (this != &other) {
            close();
            fd_ = std::exchange(other.fd_, static_cast<poll_fd_t>(-1));
            loop_ = std::exchange(other.loop_, nullptr);
        }
        return *this;
    }

    ~TcpSocket() { close(); }

    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;

    poll_fd_t fd() const { return fd_; }
    bool is_open() const { return fd_ != static_cast<poll_fd_t>(-1); }
    void set_event_loop(EventLoop* loop) { loop_ = loop; }

    void close() {
        if (fd_ != static_cast<poll_fd_t>(-1)) {
            if (loop_) loop_->unregister_fd(fd_);
#ifdef _WIN32
            closesocket(static_cast<SOCKET>(fd_));
#else
            ::close(static_cast<int>(fd_));
#endif
            fd_ = static_cast<poll_fd_t>(-1);
            loop_ = nullptr;
        }
    }

    // Awaitables for use with co_await
    class AsyncConnectAwaitable;
    class AsyncReadAwaitable;
    class AsyncWriteAwaitable;

    AsyncConnectAwaitable async_connect(EventLoop& loop, const char* host, std::uint16_t port);
    AsyncReadAwaitable async_read(EventLoop& loop, void* buf, std::size_t len);
    AsyncWriteAwaitable async_write(EventLoop& loop, const void* buf, std::size_t len);

private:
    poll_fd_t fd_;
    EventLoop* loop_;
};

class TcpListener {
public:
    TcpListener() : fd_(static_cast<poll_fd_t>(-1)), loop_(nullptr) {}
    ~TcpListener() { close(); }

    TcpListener(const TcpListener&) = delete;
    TcpListener& operator=(const TcpListener&) = delete;
    TcpListener(TcpListener&& other) noexcept
        : fd_(std::exchange(other.fd_, static_cast<poll_fd_t>(-1)))
        , loop_(std::exchange(other.loop_, nullptr)) {}
    TcpListener& operator=(TcpListener&& other) noexcept {
        if (this != &other) {
            close();
            fd_ = std::exchange(other.fd_, static_cast<poll_fd_t>(-1));
            loop_ = std::exchange(other.loop_, nullptr);
        }
        return *this;
    }

    void bind(const char* host, std::uint16_t port);
    void listen(int backlog = 128);
    void close();

    poll_fd_t fd() const { return fd_; }
    bool is_open() const { return fd_ != static_cast<poll_fd_t>(-1); }

    class AsyncAcceptAwaitable;
    AsyncAcceptAwaitable async_accept(EventLoop& loop);

private:
    poll_fd_t fd_;
    EventLoop* loop_{nullptr};
};

// --- AsyncAcceptAwaitable ---
class TcpListener::AsyncAcceptAwaitable {
public:
    AsyncAcceptAwaitable(TcpListener& listener, EventLoop& loop)
        : listener_(&listener), loop_(&loop) {}

    bool await_ready() const noexcept { return !listener_ || listener_->fd() == static_cast<poll_fd_t>(-1); }

    void await_suspend(std::coroutine_handle<> h) {
        state_ = std::make_shared<State>();
        state_->handle = h;
        state_->loop = loop_;
        state_->listener_fd = listener_->fd();
        state_->callback = [s = state_]() {
            s->loop->unregister_fd(s->listener_fd);
#ifdef _WIN32
            SOCKET client_s = accept(static_cast<SOCKET>(s->listener_fd), nullptr, nullptr);
            if (client_s != INVALID_SOCKET) {
                u_long nonblock = 1;
                ioctlsocket(client_s, FIONBIO, &nonblock);
                s->result.emplace(static_cast<poll_fd_t>(client_s), s->loop);
            }
#else
            int client_fd = ::accept(static_cast<int>(s->listener_fd), nullptr, nullptr);
            if (client_fd >= 0) {
                int flags = ::fcntl(client_fd, F_GETFL, 0);
                if (flags >= 0) ::fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
                s->result.emplace(static_cast<poll_fd_t>(client_fd), s->loop);
            }
#endif
            s->handle.resume();
        };
        loop_->register_fd(listener_->fd(), PollEvent::Read, &state_->callback,
                          std::shared_ptr<void>(state_));
    }

    TcpSocket await_resume() {
        if (state_ && state_->result) return std::move(*state_->result);
        return TcpSocket(static_cast<poll_fd_t>(-1), nullptr);
    }

private:
    struct State {
        std::coroutine_handle<> handle;
        EventLoop* loop{nullptr};
        poll_fd_t listener_fd{static_cast<poll_fd_t>(-1)};
        std::optional<TcpSocket> result;
        EventLoop::Callback callback;
    };
    TcpListener* listener_;
    EventLoop* loop_;
    std::shared_ptr<State> state_;
};

inline TcpListener::AsyncAcceptAwaitable TcpListener::async_accept(EventLoop& loop) {
    loop_ = &loop;
    return TcpListener::AsyncAcceptAwaitable(*this, loop);
}

// --- AsyncConnectAwaitable ---
class TcpSocket::AsyncConnectAwaitable {
public:
    AsyncConnectAwaitable(TcpSocket& socket, EventLoop& loop, const char* host, std::uint16_t port)
        : socket_(&socket), loop_(&loop), host_(host), port_(port) {}

    bool await_ready() const noexcept { return !socket_ || !socket_->is_open(); }

    void await_suspend(std::coroutine_handle<> h) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        if (inet_pton(AF_INET, host_, &addr.sin_addr) <= 0) {
            ec_ = std::make_error_code(std::errc::invalid_argument);
            loop_->queue_in_loop([h]() mutable { h.resume(); });
            return;
        }
#ifdef _WIN32
        int ret = connect(static_cast<SOCKET>(socket_->fd()), reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (ret == 0) {
            loop_->queue_in_loop([h]() mutable { h.resume(); });
            return;
        }
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            ec_ = std::error_code(WSAGetLastError(), std::system_category());
            loop_->queue_in_loop([h]() mutable { h.resume(); });
            return;
        }
#else
        int ret = ::connect(static_cast<int>(socket_->fd()), reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
        if (ret == 0) {
            loop_->queue_in_loop([h]() mutable { h.resume(); });
            return;
        }
        if (errno != EINPROGRESS) {
            ec_ = std::error_code(errno, std::system_category());
            loop_->queue_in_loop([h]() mutable { h.resume(); });
            return;
        }
#endif
        state_ = std::make_shared<State>();
        state_->handle = h;
        state_->loop = loop_;
        state_->fd = socket_->fd();
        state_->callback = [s = state_]() {
            s->loop->unregister_fd(s->fd);
#ifdef _WIN32
            int err = 0;
            int len = sizeof(err);
            if (getsockopt(static_cast<SOCKET>(s->fd), SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) == 0 && err != 0) {
                s->ec = std::error_code(err, std::system_category());
            }
#else
            int err = 0;
            socklen_t len = sizeof(err);
            if (getsockopt(static_cast<int>(s->fd), SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err != 0) {
                s->ec = std::error_code(err, std::system_category());
            }
#endif
            s->handle.resume();
        };
        loop_->register_fd(socket_->fd(), PollEvent::Write, &state_->callback,
                          std::shared_ptr<void>(state_));
    }

    std::error_code await_resume() {
        if (state_) return state_->ec;
        return ec_;
    }

private:
    struct State {
        std::coroutine_handle<> handle;
        EventLoop* loop{nullptr};
        poll_fd_t fd{static_cast<poll_fd_t>(-1)};
        std::error_code ec;
        EventLoop::Callback callback;
    };
    TcpSocket* socket_;
    EventLoop* loop_;
    const char* host_;
    std::uint16_t port_;
    std::shared_ptr<State> state_;
    std::error_code ec_;
};

inline TcpSocket::AsyncConnectAwaitable TcpSocket::async_connect(EventLoop& loop, const char* host, std::uint16_t port) {
    loop_ = &loop;
    return AsyncConnectAwaitable(*this, loop, host, port);
}

// --- AsyncReadAwaitable ---
class TcpSocket::AsyncReadAwaitable {
public:
    AsyncReadAwaitable(TcpSocket& socket, EventLoop& loop, void* buf, std::size_t len)
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
            int n = recv(static_cast<SOCKET>(s->fd), static_cast<char*>(s->buf), static_cast<int>(s->len), 0);
            s->result = n;
            if (n < 0) s->ec = std::error_code(WSAGetLastError(), std::system_category());
#else
            ssize_t n = ::read(static_cast<int>(s->fd), s->buf, s->len);
            s->result = static_cast<std::ptrdiff_t>(n);
            if (n < 0) s->ec = std::error_code(errno, std::system_category());
#endif
            s->handle.resume();
        };
        loop_->register_fd(socket_->fd(), PollEvent::Read, &state_->callback,
                          std::shared_ptr<void>(state_));
    }

    std::ptrdiff_t await_resume() { return state_ ? state_->result : 0; }
    std::error_code error() const { return state_ ? state_->ec : std::error_code{}; }

private:
    struct State {
        std::coroutine_handle<> handle;
        EventLoop* loop{nullptr};
        poll_fd_t fd{static_cast<poll_fd_t>(-1)};
        void* buf{nullptr};
        std::size_t len{0};
        std::ptrdiff_t result{0};
        std::error_code ec;
        EventLoop::Callback callback;
    };
    TcpSocket* socket_;
    EventLoop* loop_;
    void* buf_;
    std::size_t len_;
    std::shared_ptr<State> state_;
};

inline TcpSocket::AsyncReadAwaitable TcpSocket::async_read(EventLoop& loop, void* buf, std::size_t len) {
    loop_ = &loop;
    return AsyncReadAwaitable(*this, loop, buf, len);
}

// --- AsyncWriteAwaitable ---
class TcpSocket::AsyncWriteAwaitable {
public:
    AsyncWriteAwaitable(TcpSocket& socket, EventLoop& loop, const void* buf, std::size_t len)
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
            int n = send(static_cast<SOCKET>(s->fd), static_cast<const char*>(s->buf), static_cast<int>(s->len), 0);
            s->result = n;
            if (n < 0) s->ec = std::error_code(WSAGetLastError(), std::system_category());
#else
            ssize_t n = ::write(static_cast<int>(s->fd), s->buf, s->len);
            s->result = static_cast<std::ptrdiff_t>(n);
            if (n < 0) s->ec = std::error_code(errno, std::system_category());
#endif
            s->handle.resume();
        };
        loop_->register_fd(socket_->fd(), PollEvent::Write, &state_->callback,
                          std::shared_ptr<void>(state_));
    }

    std::ptrdiff_t await_resume() { return state_ ? state_->result : 0; }
    std::error_code error() const { return state_ ? state_->ec : std::error_code{}; }

private:
    struct State {
        std::coroutine_handle<> handle;
        EventLoop* loop{nullptr};
        poll_fd_t fd{static_cast<poll_fd_t>(-1)};
        const void* buf{nullptr};
        std::size_t len{0};
        std::ptrdiff_t result{0};
        std::error_code ec;
        EventLoop::Callback callback;
    };
    TcpSocket* socket_;
    EventLoop* loop_;
    const void* buf_;
    std::size_t len_;
    std::shared_ptr<State> state_;
};

inline TcpSocket::AsyncWriteAwaitable TcpSocket::async_write(EventLoop& loop, const void* buf, std::size_t len) {
    loop_ = &loop;
    return AsyncWriteAwaitable(*this, loop, buf, len);
}

TcpSocket make_tcp_socket();

// Type aliases per Phase 1 part 3 spec (awaitable Socket and Acceptor)
using Socket = TcpSocket;
using Acceptor = TcpListener;

}  // namespace peimon
