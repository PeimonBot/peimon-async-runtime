// Demo: Serves the test page over HTTP/1.1, HTTP/2, and HTTP/3; WebTransport over HTTP/3.
// - HTTP/1.1 (plain): http://localhost:8080/
// - HTTPS with ALPN (HTTP/1.1 or HTTP/2): https://localhost:8443/
// - HTTP/3 (QUIC/UDP): https://localhost:8444/ (e.g. curl --http3-only -k https://localhost:8444/)
// - WebTransport (HTTP/3): CONNECT :protocol=webtransport on 8444; echo for streams and datagrams.
// Build and run from build dir: cmake --build . && ./peimon_demo
// Certs: cert.pem, key.pem in build dir (generate_certs target). C++23.

#include "peimon/async_timer.hpp"
#include "peimon/event_loop.hpp"
#include "peimon/http_message.hpp"
#include "peimon/http_server.hpp"
#include "peimon/task.hpp"
#include "peimon/tcp_socket.hpp"
#include "peimon/http3_server.hpp"
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iostream>

using namespace peimon;
using namespace std::chrono_literals;

namespace {

constexpr std::string_view hello_html =
    "<!DOCTYPE html>\n"
    "<html><head><title>Hello World</title></head>\n"
    "<body><h1>Hello World</h1>\n"
    "<p>peimon-async-runtime</p>\n"
    "<ul>\n"
    "<li>HTTP/1.1 (plain) on port 8080</li>\n"
    "<li>HTTP/1.1 or HTTP/2 via ALPN over TLS on port 8443</li>\n"
    "<li>HTTP/3 (QUIC) on port 8444</li>\n"
    "<li>WebTransport over HTTP/3 on 8444 (CONNECT webtransport; echo server)</li>\n"
    "</ul></body>\n"
    "</html>";

std::string hello_handler(const HttpRequest& req) {
    (void)req;
    return make_http_ok(hello_html, "text/html; charset=utf-8");
}

Task<void> stop_after(EventLoop& loop, std::chrono::seconds delay) {
    co_await sleep_for(loop, delay);
    std::cout << "Shutting down (after " << delay.count() << "s)." << std::endl;
    std::cout.flush();
    loop.stop();
}

}  // namespace

int main() {
    const char* cert_file = "cert.pem";
    const char* key_file = "key.pem";
    if (!std::ifstream(cert_file).good() || !std::ifstream(key_file).good()) {
        std::cerr << "Missing " << cert_file << " or " << key_file
                  << ". Run from build dir and build with: cmake --build . --target generate_certs\n";
        return 1;
    }

    EventLoop loop;
    set_event_loop(&loop);

    // HTTP/1.1 plain on 8080
    HttpServerOptions opts_h1;
    opts_h1.host = "0.0.0.0";
    opts_h1.port = 8080;
    opts_h1.use_tls = false;
    opts_h1.handler = hello_handler;
    Task<void> server_h1 = run_http_server(loop, opts_h1);
    server_h1.start(loop);

    // HTTPS (ALPN h1 + h2) on 8443
    HttpServerOptions opts_h2;
    opts_h2.host = "0.0.0.0";
    opts_h2.port = 8443;
    opts_h2.use_tls = true;
    opts_h2.cert_file = cert_file;
    opts_h2.key_file = key_file;
    opts_h2.handler = hello_handler;
    Task<void> server_h2 = run_http_server(loop, opts_h2);
    server_h2.start(loop);

    // HTTP/3 (QUIC/UDP) on 8444
    run_http3_server(loop, "0.0.0.0", 8444, cert_file, key_file, hello_handler);

    Task<void> stop_task = stop_after(loop, 60s);
    stop_task.start(loop);

    std::cout << "Serving test page on:\n";
    std::cout << "  HTTP/1.1:  http://localhost:8080/\n";
    std::cout << "  HTTPS (h1/h2): https://localhost:8443/ (curl -k)\n";
    std::cout << "  HTTP/3:    https://localhost:8444/ (curl --http3-only -k)\n";
    std::cout << "  WebTransport: same origin, CONNECT webtransport (echo streams/datagrams)\n" << std::flush;

    loop.run();

    std::cout << "Done." << std::endl;
    return 0;
}
