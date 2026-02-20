#pragma once

#include "peimon/event_loop.hpp"
#include "peimon/http_message.hpp"
#include "peimon/task.hpp"
#include "peimon/tcp_socket.hpp"
#include "peimon/tls_socket.hpp"
#include <functional>
#include <memory>
#include <openssl/ssl.h>
#include <string>

namespace peimon {

/// Handler type: (request) -> response body (or full response string).
/// Return value: if it starts with "HTTP/1.1", sent as-is; otherwise wrapped in 200 OK.
using HttpHandler = std::function<std::string(const HttpRequest&)>;

/// Options for running the HTTP(S) server.
struct HttpServerOptions {
    const char* host = "0.0.0.0";
    std::uint16_t port = 8443;
    bool use_tls = true;
    const char* cert_file = nullptr;
    const char* key_file = nullptr;
    HttpHandler handler;
};

/// Run an HTTP/1.1 server: accept connections, TLS handshake if use_tls,
/// parse request, call handler, send response. One coroutine per connection.
/// Uses the existing Acceptor (TcpListener) and event loop.
Task<void> run_http_server(EventLoop& loop, HttpServerOptions options);

}  // namespace peimon
