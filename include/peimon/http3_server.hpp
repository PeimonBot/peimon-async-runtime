#pragma once

#include "peimon/event_loop.hpp"
#include "peimon/http_server.hpp"
#include <cstdint>
#include <functional>
#include <string>

namespace peimon {

/// Runs an HTTP/3 (QUIC) server on the given host/port using ngtcp2 and nghttp3.
/// Serves requests via the same HttpHandler as the HTTP/1.1 and HTTP/2 servers.
/// Supports WebTransport over HTTP/3: extended CONNECT with :protocol=webtransport
/// is accepted and answered with 200 and Capsule-Protocol; bidirectional and
/// unidirectional streams (signals 0x41 / 0x54) and HTTP/3 datagrams are echoed.
/// Uses the event loop for UDP I/O and timers. Cert and key must be PEM files.
void run_http3_server(EventLoop& loop,
                      const char* host,
                      std::uint16_t port,
                      const char* cert_file,
                      const char* key_file,
                      const HttpHandler& handler);

}  // namespace peimon
