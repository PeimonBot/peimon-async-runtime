// Functional tests for peimon-async-runtime: event loop, timers, TCP, UDP.
// Uses minimal harness (no external test framework). Exit 0 iff all pass.
// HTTP/3 tests are in a separate optional binary when PEIMON_BUILD_HTTP3.

#include "peimon/async_timer.hpp"
#include "peimon/event_loop.hpp"
#include "peimon/task.hpp"
#include "peimon/tcp_socket.hpp"
#include "peimon/udp_socket.hpp"
#include "test_harness.hpp"

#include <chrono>
#include <cstring>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace peimon;
using namespace std::chrono_literals;

namespace {

// --- Event loop tests ---
void test_run_in_loop_and_stop() {
    std::cerr << "  [LOG] test_run_in_loop_and_stop: start\n";
    EventLoop loop;
    bool ran = false;
    std::cerr << "  [LOG] test_run_in_loop_and_stop: run_in_loop\n";
    loop.run_in_loop([&]() {
        ran = true;
        ASSERT(loop.running());
        loop.stop();
    });
    ASSERT(!loop.running());
    std::cerr << "  [LOG] test_run_in_loop_and_stop: loop.run()\n";
    loop.run();
    ASSERT(ran);
    ASSERT(!loop.running());
    std::cerr << "  [LOG] test_run_in_loop_and_stop: done\n";
}

void test_queue_in_loop_order() {
    std::cerr << "  [LOG] test_queue_in_loop_order: start\n";
    EventLoop loop;
    std::vector<int> order;
    loop.run_after(50ms, [&]() { order.push_back(1); });
    loop.run_after(100ms, [&]() { order.push_back(2); });
    loop.run_after(150ms, [&]() {
        order.push_back(3);
        loop.stop();
    });
    std::cerr << "  [LOG] test_queue_in_loop_order: loop.run()\n";
    loop.run();
    ASSERT(order.size() == 3u);
    ASSERT(order[0] == 1 && order[1] == 2 && order[2] == 3);
    std::cerr << "  [LOG] test_queue_in_loop_order: done\n";
}

void test_run_after_fires() {
    std::cerr << "  [LOG] test_run_after_fires: start\n";
    EventLoop loop;
    bool fired = false;
    loop.run_after(50ms, [&]() {
        fired = true;
        loop.stop();
    });
    std::cerr << "  [LOG] test_run_after_fires: loop.run()\n";
    loop.run();
    ASSERT(fired);
    std::cerr << "  [LOG] test_run_after_fires: done\n";
}

void test_multiple_run_after_order() {
    std::cerr << "  [LOG] test_multiple_run_after_order: start\n";
    EventLoop loop;
    std::vector<int> order;
    loop.run_after(150ms, [&]() {
        order.push_back(3);
        if (order.size() == 3u) loop.stop();
    });
    loop.run_after(50ms, [&]() { order.push_back(1); });
    loop.run_after(100ms, [&]() { order.push_back(2); });
    std::cerr << "  [LOG] test_multiple_run_after_order: loop.run()\n";
    loop.run();
    ASSERT(order.size() == 3u);
    ASSERT(order[0] == 1 && order[1] == 2 && order[2] == 3);
    std::cerr << "  [LOG] test_multiple_run_after_order: done\n";
}

// --- Timer (sleep_for) coroutine test ---
Task<void> sleep_for_task(EventLoop& loop, std::chrono::milliseconds delay, bool* flag) {
    co_await sleep_for(loop, delay);
    *flag = true;
}

void test_sleep_for_coroutine() {
    std::cerr << "  [LOG] test_sleep_for_coroutine: start\n";
    EventLoop loop;
    set_event_loop(&loop);
    bool flag = false;
    Task<void> t = sleep_for_task(loop, 20ms, &flag);
    t.start(loop);
    loop.run_after(100ms, [&loop]() { loop.stop(); });
    std::cerr << "  [LOG] test_sleep_for_coroutine: loop.run()\n";
    loop.run();
    ASSERT(flag);
    std::cerr << "  [LOG] test_sleep_for_coroutine: done\n";
}

// --- TCP tests (listener + client echo) ---
constexpr std::uint16_t TCP_TEST_PORT = 19090;

// Delay before server closes the client socket so the peer can read the echo before EOF.
// Needed on macOS/kqueue and helps on other platforms with different TCP shutdown ordering.
// Use a delay long enough for CI (macOS runner may schedule timers and I/O with more latency).
constexpr auto TCP_SERVER_CLOSE_DELAY = 200ms;

// Read exactly n bytes (handles partial reads on kqueue/epoll/non-blocking sockets).
// Returns bytes read, or <=0 on error/EOF. Caller must treat 0 as connection closed.
Task<std::ptrdiff_t> tcp_read_n(EventLoop& loop, TcpSocket& sock, void* buf, std::size_t n) {
    std::size_t total = 0;
    char* p = static_cast<char*>(buf);
    while (total < n && sock.is_open()) {
        std::ptrdiff_t r = co_await sock.async_read(loop, p + total, n - total);
        if (r <= 0) co_return total > 0 ? static_cast<std::ptrdiff_t>(total) : r;
        total += static_cast<std::size_t>(r);
    }
    co_return static_cast<std::ptrdiff_t>(total);
}

// Write exactly n bytes (handles partial writes).
Task<std::ptrdiff_t> tcp_write_n(EventLoop& loop, TcpSocket& sock, const void* buf, std::size_t n) {
    std::size_t total = 0;
    const char* p = static_cast<const char*>(buf);
    while (total < n && sock.is_open()) {
        std::ptrdiff_t w = co_await sock.async_write(loop, p + total, n - total);
        if (w <= 0) co_return total > 0 ? static_cast<std::ptrdiff_t>(total) : w;
        total += static_cast<std::size_t>(w);
    }
    co_return static_cast<std::ptrdiff_t>(total);
}

Task<void> tcp_server_task(EventLoop& loop, TcpListener& listener, bool* accepted, bool* echoed) {
    std::cerr << "  [LOG] tcp_server_task: async_accept\n";
    TcpSocket client = co_await listener.async_accept(loop);
    std::cerr << "  [LOG] tcp_server_task: accepted\n";
    *accepted = true;
    ASSERT(client.is_open());
    char buf[64];
    static constexpr std::size_t buf_size = sizeof(buf);
    std::cerr << "  [LOG] tcp_server_task: async_read\n";
    std::ptrdiff_t n = co_await tcp_read_n(loop, client, buf, buf_size);
    std::cerr << "  [LOG] tcp_server_task: read " << n << " bytes\n";
    ASSERT_MSG(n > 0, "TCP server read must receive at least 1 byte");
    ASSERT_MSG(n <= static_cast<std::ptrdiff_t>(buf_size), "TCP server read must not exceed buffer");
    std::cerr << "  [LOG] tcp_server_task: async_write\n";
    std::ptrdiff_t w = co_await tcp_write_n(loop, client, buf, static_cast<std::size_t>(n));
    std::cerr << "  [LOG] tcp_server_task: wrote " << w << " bytes\n";
    ASSERT_MSG(w == n, "TCP server must echo full read count");
    ASSERT(client.is_open());
    *echoed = true;
    // Delay closing so the client can read the echo before seeing EOF (see TCP_SERVER_CLOSE_DELAY).
    // Wrap in shared_ptr so the timer callback is copyable (required by std::function).
    auto client_ptr = std::make_shared<TcpSocket>(std::move(client));
    loop.run_after(TCP_SERVER_CLOSE_DELAY, [client_ptr]() { client_ptr->close(); });
    std::cerr << "  [LOG] tcp_server_task: done\n";
}

Task<void> tcp_client_task(EventLoop& loop, bool* connected, bool* received) {
    std::cerr << "  [LOG] tcp_client_task: make_tcp_socket, async_connect\n";
    TcpSocket sock = make_tcp_socket();
    ASSERT(sock.is_open());
    std::error_code ec = co_await sock.async_connect(loop, "127.0.0.1", TCP_TEST_PORT);
    std::cerr << "  [LOG] tcp_client_task: connect done, ec=" << ec.message() << "\n";
    ASSERT_MSG(!ec, "TCP client connect must succeed");
    *connected = true;
    const char* msg = "hello";
    std::size_t len = std::strlen(msg);
    ASSERT(len > 0u && len < 64u);
    std::cerr << "  [LOG] tcp_client_task: async_write\n";
    std::ptrdiff_t w = co_await tcp_write_n(loop, sock, msg, len);
    std::cerr << "  [LOG] tcp_client_task: wrote " << w << "\n";
    ASSERT_MSG(w == static_cast<std::ptrdiff_t>(len), "TCP client must write full message");
    char buf[64];
    std::cerr << "  [LOG] tcp_client_task: async_read\n";
    std::ptrdiff_t n = co_await tcp_read_n(loop, sock, buf, len);
    std::cerr << "  [LOG] tcp_client_task: read " << n << "\n";
    ASSERT_MSG(n == static_cast<std::ptrdiff_t>(len), "TCP client must read full echo");
    ASSERT_MSG(n >= 0 && static_cast<std::size_t>(n) < sizeof(buf), "TCP read count in range for null term");
    buf[static_cast<std::size_t>(n)] = '\0';
    ASSERT(std::strcmp(buf, msg) == 0);
    *received = true;
    sock.close();
    loop.stop();
    std::cerr << "  [LOG] tcp_client_task: done\n";
}

void test_tcp_echo() {
    std::cerr << "  [LOG] test_tcp_echo: start\n";
    EventLoop loop;
    set_event_loop(&loop);
    std::cerr << "  [LOG] test_tcp_echo: bind and listen\n";
    TcpListener listener;
    listener.bind("127.0.0.1", TCP_TEST_PORT);
    listener.listen(1);
    bool accepted = false, echoed = false, connected = false, received = false;
    bool timed_out = false;
    std::cerr << "  [LOG] test_tcp_echo: start server task\n";
    Task<void> server = tcp_server_task(loop, listener, &accepted, &echoed);
    server.start(loop);
    Task<void> client;  // keep alive so start() callback does not use stack-after-return
    // Platform-dependent delay: listener must be ready; on Windows the WSAEventSelect/IOCP
    // bridge thread needs time to include the listener in its wait set and to pick up
    // accepted client sockets, so use a longer delay there.
#ifdef _WIN32
    const auto client_delay = 500ms;
#else
    const auto client_delay = 50ms;
#endif
    const auto timeout = 10000ms;  // Safety: fail instead of hang on slow CI
    std::cerr << "  [LOG] test_tcp_echo: schedule client in " << client_delay.count() << "ms\n";
    loop.run_after(client_delay, [&]() {
        client = tcp_client_task(loop, &connected, &received);
        client.start(loop);
    });
    loop.run_after(timeout, [&]() {
        if (!received) {
            timed_out = true;
            loop.stop();
        }
    });
    std::cerr << "  [LOG] test_tcp_echo: loop.run()\n";
    loop.run();
    std::cerr << "  [LOG] test_tcp_echo: loop exited, accepted=" << accepted << " echoed=" << echoed
              << " connected=" << connected << " received=" << received << " timed_out=" << timed_out << "\n";

    // Clean up listener and port first so they are released even on timeout or assertion failure.
    listener.close();

    ASSERT_MSG(!timed_out, "TCP echo test timed out");
    ASSERT_MSG(accepted, "TCP echo test: server must accept a connection");
    ASSERT_MSG(echoed, "TCP echo test: server must echo back received data");
    ASSERT_MSG(connected, "TCP echo test: client must connect");
    ASSERT_MSG(received, "TCP echo test: client must receive echo");
    std::cerr << "  [LOG] test_tcp_echo: done\n";
}

// --- UDP tests ---
constexpr std::uint16_t UDP_RECV_PORT = 19091;
constexpr std::uint16_t UDP_SEND_PORT = 19092;

Task<void> udp_recv_task(EventLoop& loop, UdpSocket& recv_sock, bool* got, std::string* payload) {
    char buf[256];
    UdpRecvResult r = co_await recv_sock.async_recv_from(loop, buf, sizeof(buf));
    ASSERT(r.bytes > 0);
    payload->assign(buf, static_cast<std::size_t>(r.bytes));
    *got = true;
    loop.stop();
}

Task<void> udp_send_task(EventLoop& loop, UdpSocket& send_sock, const sockaddr* addr, socklen_t addrlen,
                         const char* msg, bool* sent) {
    std::size_t len = std::strlen(msg);
    std::ptrdiff_t n = co_await send_sock.async_send_to(loop, msg, len, addr, addrlen);
    ASSERT(n == static_cast<std::ptrdiff_t>(len));
    *sent = true;
}

void test_udp_send_recv() {
    std::cerr << "  [LOG] test_udp_send_recv: start\n";
    EventLoop loop;
    set_event_loop(&loop);
    std::cerr << "  [LOG] test_udp_send_recv: bind sockets\n";
    UdpSocket recv_sock;
    recv_sock.bind("127.0.0.1", UDP_RECV_PORT);
    recv_sock.set_event_loop(&loop);

    UdpSocket send_sock;
    send_sock.bind("127.0.0.1", UDP_SEND_PORT);
    send_sock.set_event_loop(&loop);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(UDP_RECV_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    bool got = false, sent = false;
    std::string payload;
    Task<void> r = udp_recv_task(loop, recv_sock, &got, &payload);
    r.start(loop);
    Task<void> s;  // keep alive so start() callback does not use stack-after-return
    // Delay so recv is registered before send (resilient to timing across runners).
    std::cerr << "  [LOG] test_udp_send_recv: start recv, schedule send in 50ms\n";
    loop.run_after(50ms, [&]() {
        s = udp_send_task(loop, send_sock,
                          reinterpret_cast<const sockaddr*>(&addr), sizeof(addr),
                          "udp_hello", &sent);
        s.start(loop);
    });
    std::cerr << "  [LOG] test_udp_send_recv: loop.run()\n";
    loop.run();
    ASSERT(sent);
    ASSERT(got);
    ASSERT(payload == "udp_hello");
    std::cerr << "  [LOG] test_udp_send_recv: done\n";
    // Unregister and close so ports are released.
    recv_sock.close();
    send_sock.close();
}

}  // namespace

int main() {
    std::cout << "peimon-async-runtime functional tests\n";
    std::cerr << "[LOG] main: starting tests\n";

    std::cerr << "[LOG] main: RUN_TEST event_loop run_in_loop and stop\n";
    RUN_TEST("event_loop run_in_loop and stop", test_run_in_loop_and_stop());
    std::cerr << "[LOG] main: RUN_TEST queue_in_loop order\n";
    RUN_TEST("queue_in_loop order", test_queue_in_loop_order());
    std::cerr << "[LOG] main: RUN_TEST run_after fires\n";
    RUN_TEST("run_after fires", test_run_after_fires());
    std::cerr << "[LOG] main: RUN_TEST multiple run_after order\n";
    RUN_TEST("multiple run_after order", test_multiple_run_after_order());
    std::cerr << "[LOG] main: RUN_TEST sleep_for coroutine\n";
    RUN_TEST("sleep_for coroutine", test_sleep_for_coroutine());
    std::cerr << "[LOG] main: RUN_TEST TCP echo\n";
    RUN_TEST("TCP echo", test_tcp_echo());
    std::cerr << "[LOG] main: RUN_TEST UDP send/recv\n";
    RUN_TEST("UDP send/recv", test_udp_send_recv());

    std::cerr << "[LOG] main: all tests passed\n";
    std::cout << "All tests passed.\n";
    return 0;
}
