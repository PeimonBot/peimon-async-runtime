#pragma once

#include "peimon/event_loop.hpp"
#include "peimon/tcp_socket.hpp"
#include <coroutine>
#include <memory>
#include <optional>
#include <system_error>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace peimon {

/// RAII wrapper for OpenSSL SSL_CTX (server or client).
class TlsContext {
public:
    TlsContext() = default;
    explicit TlsContext(SSL_CTX* ctx) : ctx_(ctx) {}
    ~TlsContext() { reset(); }

    TlsContext(TlsContext&& other) noexcept : ctx_(std::exchange(other.ctx_, nullptr)) {}
    TlsContext& operator=(TlsContext&& other) noexcept {
        if (this != &other) {
            reset();
            ctx_ = std::exchange(other.ctx_, nullptr);
        }
        return *this;
    }
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;

    SSL_CTX* get() const { return ctx_; }
    explicit operator bool() const { return ctx_ != nullptr; }

    void reset() {
        if (ctx_) {
            SSL_CTX_free(ctx_);
            ctx_ = nullptr;
        }
    }

private:
    SSL_CTX* ctx_{nullptr};
};

/// Create a server TLS context and load cert + key from PEM files.
/// Returns null on failure (check ERR_get_error()).
TlsContext make_tls_server_context(const char* cert_file, const char* key_file);

/// TLS wrapper around TcpSocket. Provides async read/write and server handshake.
class TlsSocket {
public:
    TlsSocket() = default;
    /// Takes ownership of \a socket and \a ssl. SSL must have fd set via SSL_set_fd(ssl, socket.fd()).
    TlsSocket(TcpSocket&& socket, SSL* ssl);

    TlsSocket(TlsSocket&& other) noexcept;
    TlsSocket& operator=(TlsSocket&& other) noexcept;
    ~TlsSocket();

    TlsSocket(const TlsSocket&) = delete;
    TlsSocket& operator=(const TlsSocket&) = delete;

    int fd() const { return socket_.fd(); }
    bool is_open() const { return socket_.is_open() && ssl_; }
    void close();

    /// Returns true if ALPN negotiated "h2" (HTTP/2); false for "http/1.1" or no ALPN.
    bool is_http2_negotiated() const;

    void set_event_loop(EventLoop* loop) { socket_.set_event_loop(loop); }

    class AsyncHandshakeAwaitable;
    class AsyncReadAwaitable;
    class AsyncWriteAwaitable;

    AsyncHandshakeAwaitable async_handshake_server(EventLoop& loop);
    AsyncReadAwaitable async_read(EventLoop& loop, void* buf, std::size_t len);
    AsyncWriteAwaitable async_write(EventLoop& loop, const void* buf, std::size_t len);

private:
    TcpSocket socket_;
    SSL* ssl_{nullptr};
};

// --- AsyncHandshakeAwaitable (SSL_accept with suspend on WANT_READ/WANT_WRITE) ---
class TlsSocket::AsyncHandshakeAwaitable {
public:
    AsyncHandshakeAwaitable(TlsSocket& socket, EventLoop& loop) : socket_(&socket), loop_(&loop) {}

    bool await_ready() const noexcept { return !socket_ || !socket_->is_open(); }

    void await_suspend(std::coroutine_handle<> h);
    std::error_code await_resume();

private:
    void try_accept();

    TlsSocket* socket_;
    EventLoop* loop_;
    std::shared_ptr<struct HandshakeState> state_;
};

inline TlsSocket::AsyncHandshakeAwaitable TlsSocket::async_handshake_server(EventLoop& loop) {
    socket_.set_event_loop(&loop);
    return AsyncHandshakeAwaitable(*this, loop);
}

// --- AsyncReadAwaitable ---
class TlsSocket::AsyncReadAwaitable {
public:
    AsyncReadAwaitable(TlsSocket& socket, EventLoop& loop, void* buf, std::size_t len)
        : socket_(&socket), loop_(&loop), buf_(buf), len_(len) {}

    bool await_ready() const noexcept { return !socket_ || !socket_->is_open() || len_ == 0; }

    void await_suspend(std::coroutine_handle<> h);
    std::ptrdiff_t await_resume();
    std::error_code error() const;

private:
    void try_read();

    TlsSocket* socket_;
    EventLoop* loop_;
    void* buf_;
    std::size_t len_;
    std::shared_ptr<struct TlsReadState> state_;
};

inline TlsSocket::AsyncReadAwaitable TlsSocket::async_read(EventLoop& loop, void* buf, std::size_t len) {
    socket_.set_event_loop(&loop);
    return AsyncReadAwaitable(*this, loop, buf, len);
}

// --- AsyncWriteAwaitable ---
class TlsSocket::AsyncWriteAwaitable {
public:
    AsyncWriteAwaitable(TlsSocket& socket, EventLoop& loop, const void* buf, std::size_t len)
        : socket_(&socket), loop_(&loop), buf_(buf), len_(len) {}

    bool await_ready() const noexcept { return !socket_ || !socket_->is_open() || len_ == 0; }

    void await_suspend(std::coroutine_handle<> h);
    std::ptrdiff_t await_resume();
    std::error_code error() const;

private:
    void try_write();

    TlsSocket* socket_;
    EventLoop* loop_;
    const void* buf_;
    std::size_t len_;
    std::shared_ptr<struct TlsWriteState> state_;
};

inline TlsSocket::AsyncWriteAwaitable TlsSocket::async_write(EventLoop& loop, const void* buf, std::size_t len) {
    socket_.set_event_loop(&loop);
    return AsyncWriteAwaitable(*this, loop, buf, len);
}

}  // namespace peimon
