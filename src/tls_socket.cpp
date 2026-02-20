#include "peimon/tls_socket.hpp"
#include "peimon/event_loop.hpp"
#include <nghttp2/nghttp2.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>

namespace peimon {

namespace {

// ALPN select callback: choose "h2" or "http/1.1" and store choice in SSL app data.
// Non-null app data => h2 was selected; null => http/1.1.
int alpn_select_cb(SSL* ssl, const unsigned char** out, unsigned char* outlen,
                   const unsigned char* in, unsigned int inlen, void* /*arg*/) {
    int rv = nghttp2_select_alpn(out, outlen, in, inlen);
    if (rv == -1)
        return SSL_TLSEXT_ERR_NOACK;
    SSL_set_app_data(ssl, (rv == 1) ? reinterpret_cast<void*>(1) : nullptr);
    return SSL_TLSEXT_ERR_OK;
}

}  // namespace

// -----------------------------------------------------------------------------
// TlsContext
// -----------------------------------------------------------------------------
TlsContext make_tls_server_context(const char* cert_file, const char* key_file) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (OPENSSL_init_ssl(0, nullptr) != 1) return TlsContext(nullptr);
#endif
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return TlsContext(nullptr);
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        return TlsContext(nullptr);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        return TlsContext(nullptr);
    }
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, nullptr);
    return TlsContext(ctx);
}

bool TlsSocket::is_http2_negotiated() const {
    return ssl_ && SSL_get_app_data(ssl_) != nullptr;
}

// -----------------------------------------------------------------------------
// TlsSocket
// -----------------------------------------------------------------------------
TlsSocket::TlsSocket(TcpSocket&& socket, SSL* ssl) : socket_(std::move(socket)), ssl_(ssl) {}

TlsSocket::TlsSocket(TlsSocket&& other) noexcept
    : socket_(std::move(other.socket_)), ssl_(std::exchange(other.ssl_, nullptr)) {}

TlsSocket& TlsSocket::operator=(TlsSocket&& other) noexcept {
    if (this != &other) {
        close();
        socket_ = std::move(other.socket_);
        ssl_ = std::exchange(other.ssl_, nullptr);
    }
    return *this;
}

TlsSocket::~TlsSocket() { close(); }

void TlsSocket::close() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    socket_.close();
}

// -----------------------------------------------------------------------------
// AsyncHandshakeAwaitable state and implementation
// -----------------------------------------------------------------------------
struct HandshakeState {
    std::coroutine_handle<> handle;
    EventLoop* loop{nullptr};
    int fd{-1};
    bool registered{false};
    std::error_code ec;
    EventLoop::Callback callback;
};

void TlsSocket::AsyncHandshakeAwaitable::try_accept() {
    int ret = SSL_accept(socket_->ssl_);
    if (ret == 1) {
        if (state_->registered && state_->loop) state_->loop->unregister_fd(socket_->fd());
        state_->registered = false;
        state_->handle.resume();
        return;
    }
    int err = SSL_get_error(socket_->ssl_, ret);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        state_->ec = std::error_code(static_cast<int>(ERR_get_error()), std::system_category());
        if (state_->registered && state_->loop) state_->loop->unregister_fd(socket_->fd());
        state_->registered = false;
        state_->handle.resume();
        return;
    }
    PollEvent ev = (err == SSL_ERROR_WANT_READ) ? PollEvent::Read : PollEvent::Write;
    state_->callback = [this]() { try_accept(); };
    if (state_->registered)
        state_->loop->modify_fd(socket_->fd(), ev, &state_->callback);
    else {
        state_->loop->register_fd(socket_->fd(), ev, &state_->callback);
        state_->registered = true;
    }
}

void TlsSocket::AsyncHandshakeAwaitable::await_suspend(std::coroutine_handle<> h) {
    state_ = std::make_shared<HandshakeState>();
    state_->handle = h;
    state_->loop = loop_;
    state_->callback = [this]() { try_accept(); };
    try_accept();
}

std::error_code TlsSocket::AsyncHandshakeAwaitable::await_resume() {
    return state_ ? state_->ec : std::error_code{};
}

// -----------------------------------------------------------------------------
// AsyncReadAwaitable state and implementation
// -----------------------------------------------------------------------------
struct TlsReadState {
    std::coroutine_handle<> handle;
    EventLoop* loop{nullptr};
    int fd{-1};
    bool registered{false};
    ssize_t result{0};
    std::error_code ec;
    EventLoop::Callback callback;
};

void TlsSocket::AsyncReadAwaitable::try_read() {
    int n = SSL_read(socket_->ssl_, buf_, static_cast<int>(len_));
    if (n > 0) {
        if (state_->registered && state_->loop) state_->loop->unregister_fd(socket_->fd());
        state_->registered = false;
        state_->result = n;
        state_->handle.resume();
        return;
    }
    int err = SSL_get_error(socket_->ssl_, n);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        state_->ec = (err == SSL_ERROR_ZERO_RETURN)
                         ? std::error_code{}
                         : std::error_code(static_cast<int>(ERR_get_error()), std::system_category());
        if (state_->registered && state_->loop) state_->loop->unregister_fd(socket_->fd());
        state_->registered = false;
        state_->handle.resume();
        return;
    }
    PollEvent ev = (err == SSL_ERROR_WANT_READ) ? PollEvent::Read : PollEvent::Write;
    state_->callback = [this]() { try_read(); };
    if (state_->registered)
        state_->loop->modify_fd(socket_->fd(), ev, &state_->callback);
    else {
        state_->loop->register_fd(socket_->fd(), ev, &state_->callback);
        state_->registered = true;
    }
}

void TlsSocket::AsyncReadAwaitable::await_suspend(std::coroutine_handle<> h) {
    state_ = std::make_shared<TlsReadState>();
    state_->handle = h;
    state_->loop = loop_;
    state_->callback = [this]() { try_read(); };
    try_read();
}

std::ptrdiff_t TlsSocket::AsyncReadAwaitable::await_resume() {
    return state_ ? state_->result : 0;
}

std::error_code TlsSocket::AsyncReadAwaitable::error() const {
    return state_ ? state_->ec : std::error_code{};
}

// -----------------------------------------------------------------------------
// AsyncWriteAwaitable state and implementation
// -----------------------------------------------------------------------------
struct TlsWriteState {
    std::coroutine_handle<> handle;
    EventLoop* loop{nullptr};
    int fd{-1};
    bool registered{false};
    ssize_t result{0};
    std::error_code ec;
    EventLoop::Callback callback;
};

void TlsSocket::AsyncWriteAwaitable::try_write() {
    int n = SSL_write(socket_->ssl_, buf_, static_cast<int>(len_));
    if (n > 0) {
        if (state_->registered && state_->loop) state_->loop->unregister_fd(socket_->fd());
        state_->registered = false;
        state_->result = n;
        state_->handle.resume();
        return;
    }
    int err = SSL_get_error(socket_->ssl_, n);
    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
        state_->ec = std::error_code(static_cast<int>(ERR_get_error()), std::system_category());
        if (state_->registered && state_->loop) state_->loop->unregister_fd(socket_->fd());
        state_->registered = false;
        state_->handle.resume();
        return;
    }
    PollEvent ev = (err == SSL_ERROR_WANT_READ) ? PollEvent::Read : PollEvent::Write;
    state_->callback = [this]() { try_write(); };
    if (state_->registered)
        state_->loop->modify_fd(socket_->fd(), ev, &state_->callback);
    else {
        state_->loop->register_fd(socket_->fd(), ev, &state_->callback);
        state_->registered = true;
    }
}

void TlsSocket::AsyncWriteAwaitable::await_suspend(std::coroutine_handle<> h) {
    state_ = std::make_shared<TlsWriteState>();
    state_->handle = h;
    state_->loop = loop_;
    state_->callback = [this]() { try_write(); };
    try_write();
}

std::ptrdiff_t TlsSocket::AsyncWriteAwaitable::await_resume() {
    return state_ ? state_->result : 0;
}

std::error_code TlsSocket::AsyncWriteAwaitable::error() const {
    return state_ ? state_->ec : std::error_code{};
}

}  // namespace peimon
