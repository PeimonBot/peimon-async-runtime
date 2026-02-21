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
    EventLoop loop;
    bool ran = false;
    loop.run_in_loop([&]() {
        ran = true;
        ASSERT(loop.running());
        loop.stop();
    });
    ASSERT(!loop.running());
    loop.run();
    ASSERT(ran);
    ASSERT(!loop.running());
}

void test_queue_in_loop_order() {
    // Test that scheduled callbacks run in order (run_after with distinct delays).
    EventLoop loop;
    std::vector<int> order;
    loop.run_after(50ms, [&]() { order.push_back(1); });
    loop.run_after(100ms, [&]() { order.push_back(2); });
    loop.run_after(150ms, [&]() {
        order.push_back(3);
        loop.stop();
    });
    loop.run();
    ASSERT(order.size() == 3u);
    ASSERT(order[0] == 1 && order[1] == 2 && order[2] == 3);
}

void test_run_after_fires() {
    EventLoop loop;
    bool fired = false;
    loop.run_after(50ms, [&]() {
        fired = true;
        loop.stop();
    });
    loop.run();
    ASSERT(fired);
}

void test_multiple_run_after_order() {
    EventLoop loop;
    std::vector<int> order;
    loop.run_after(150ms, [&]() {
        order.push_back(3);
        if (order.size() == 3u) loop.stop();
    });
    loop.run_after(50ms, [&]() { order.push_back(1); });
    loop.run_after(100ms, [&]() { order.push_back(2); });
    loop.run();
    ASSERT(order.size() == 3u);
    ASSERT(order[0] == 1 && order[1] == 2 && order[2] == 3);
}

// --- Timer (sleep_for) coroutine test ---
Task<void> sleep_for_task(EventLoop& loop, std::chrono::milliseconds delay, bool* flag) {
    co_await sleep_for(loop, delay);
    *flag = true;
}

void test_sleep_for_coroutine() {
    EventLoop loop;
    set_event_loop(&loop);
    bool flag = false;
    Task<void> t = sleep_for_task(loop, 20ms, &flag);
    t.start(loop);
    loop.run_after(100ms, [&loop]() { loop.stop(); });
    loop.run();
    ASSERT(flag);
}

// --- TCP tests (listener + client echo) ---
constexpr std::uint16_t TCP_TEST_PORT = 19090;

Task<void> tcp_server_task(EventLoop& loop, TcpListener& listener, bool* accepted, bool* echoed) {
    TcpSocket client = co_await listener.async_accept(loop);
    *accepted = true;
    ASSERT(client.is_open());
    char buf[64];
    std::ptrdiff_t n = co_await client.async_read(loop, buf, sizeof(buf));
    ASSERT(n > 0);
    std::ptrdiff_t w = co_await client.async_write(loop, buf, static_cast<std::size_t>(n));
    ASSERT(w == n);
    *echoed = true;
    client.close();
}

Task<void> tcp_client_task(EventLoop& loop, bool* connected, bool* received) {
    TcpSocket sock = make_tcp_socket();
    std::error_code ec = co_await sock.async_connect(loop, "127.0.0.1", TCP_TEST_PORT);
    ASSERT(!ec);
    *connected = true;
    const char* msg = "hello";
    std::size_t len = std::strlen(msg);
    std::ptrdiff_t w = co_await sock.async_write(loop, msg, len);
    ASSERT(w == static_cast<std::ptrdiff_t>(len));
    char buf[64];
    std::ptrdiff_t n = co_await sock.async_read(loop, buf, sizeof(buf));
    ASSERT(n == static_cast<std::ptrdiff_t>(len));
    buf[n] = '\0';
    ASSERT(std::strcmp(buf, msg) == 0);
    *received = true;
    sock.close();
    loop.stop();
}

void test_tcp_echo() {
    EventLoop loop;
    set_event_loop(&loop);
    TcpListener listener;
    listener.bind("127.0.0.1", TCP_TEST_PORT);
    listener.listen(1);
    bool accepted = false, echoed = false, connected = false, received = false;
    Task<void> server = tcp_server_task(loop, listener, &accepted, &echoed);
    server.start(loop);
    Task<void> client;  // keep alive so start() callback does not use stack-after-return
    loop.run_after(20ms, [&]() {
        client = tcp_client_task(loop, &connected, &received);
        client.start(loop);
    });
    loop.run();
    ASSERT(accepted);
    ASSERT(echoed);
    ASSERT(connected);
    ASSERT(received);
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
    EventLoop loop;
    set_event_loop(&loop);
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
    loop.run_after(20ms, [&]() {
        s = udp_send_task(loop, send_sock,
                          reinterpret_cast<const sockaddr*>(&addr), sizeof(addr),
                          "udp_hello", &sent);
        s.start(loop);
    });
    loop.run();
    ASSERT(sent);
    ASSERT(got);
    ASSERT(payload == "udp_hello");
}

}  // namespace

int main() {
    std::cout << "peimon-async-runtime functional tests\n";

    RUN_TEST("event_loop run_in_loop and stop", test_run_in_loop_and_stop());
    RUN_TEST("queue_in_loop order", test_queue_in_loop_order());
    RUN_TEST("run_after fires", test_run_after_fires());
    RUN_TEST("multiple run_after order", test_multiple_run_after_order());
    RUN_TEST("sleep_for coroutine", test_sleep_for_coroutine());
    RUN_TEST("TCP echo", test_tcp_echo());
    RUN_TEST("UDP send/recv", test_udp_send_recv());

    std::cout << "All tests passed.\n";
    return 0;
}
