// HTTP/3 smoke test: only built when PEIMON_BUILD_HTTP3 is ON.
// Starts the server, runs the loop briefly, then stops. Verifies no crash.
// Requires cert.pem and key.pem in current directory (e.g. from generate_certs).

#if !defined(PEIMON_BUILD_HTTP3) || !PEIMON_BUILD_HTTP3
int main() { return 0; }  // skip when HTTP/3 not built
#else

#include "peimon/event_loop.hpp"
#include "peimon/http3_server.hpp"
#include "peimon/http_message.hpp"
#include "peimon/async_timer.hpp"
#include "peimon/task.hpp"
#include "test_harness.hpp"
#include <chrono>
#include <fstream>
#include <iostream>

using namespace peimon;
using namespace std::chrono_literals;

namespace {

std::string dummy_handler(const HttpRequest&) {
    return make_http_ok("ok", "text/plain");
}

Task<void> stop_after(EventLoop& loop, std::chrono::milliseconds delay) {
    co_await sleep_for(loop, delay);
    loop.stop();
}

}  // namespace

int main() {
    const char* cert = "cert.pem";
    const char* key = "key.pem";
    if (!std::ifstream(cert).good() || !std::ifstream(key).good()) {
        std::cerr << "HTTP/3 smoke test needs cert.pem and key.pem (run generate_certs). Skipping.\n";
        return 0;
    }
    EventLoop loop;
    set_event_loop(&loop);
    run_http3_server(loop, "127.0.0.1", 19443, cert, key, dummy_handler);
    Task<void> stop_task = stop_after(loop, 500ms);
    stop_task.start(loop);
    loop.run();
    std::cout << "HTTP/3 smoke test ok\n";
    return 0;
}

#endif
