#include "peimon/tcp_socket.hpp"
#include <stdexcept>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

namespace peimon {

namespace {

#ifdef _WIN32
void ensure_winsock() {
    static const bool ok = []() {
        WSADATA d{};
        return WSAStartup(MAKEWORD(2, 2), &d) == 0;
    }();
    if (!ok) throw std::runtime_error("WSAStartup failed");
}
#endif

poll_fd_t create_tcp_socket() {
#ifdef _WIN32
    ensure_winsock();
    SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) {
        throw std::runtime_error("WSASocket failed");
    }
    u_long nonblock = 1;
    if (ioctlsocket(s, FIONBIO, &nonblock) != 0) {
        closesocket(s);
        throw std::runtime_error("ioctlsocket FIONBIO failed");
    }
    return static_cast<poll_fd_t>(s);
#else
    int fd = ::socket(AF_INET,
#if defined(SOCK_CLOEXEC) && !defined(__APPLE__)
                      SOCK_STREAM | SOCK_CLOEXEC,
#else
                      SOCK_STREAM,
#endif
                      0);
    if (fd < 0) {
        throw std::runtime_error(std::string("socket: ") + std::strerror(errno));
    }
#if !defined(SOCK_CLOEXEC) || defined(__APPLE__)
    {
        int flags = ::fcntl(fd, F_GETFD, 0);
        if (flags >= 0) ::fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
#endif
    {
        int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    return static_cast<poll_fd_t>(fd);
#endif
}

}  // namespace

void TcpListener::bind(const char* host, std::uint16_t port) {
    if (fd_ != static_cast<poll_fd_t>(-1)) return;
    fd_ = create_tcp_socket();
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
#ifdef _WIN32
        closesocket(static_cast<SOCKET>(fd_));
#else
        ::close(static_cast<int>(fd_));
#endif
        fd_ = static_cast<poll_fd_t>(-1);
        throw std::runtime_error("inet_pton failed");
    }
    int one = 1;
#ifdef _WIN32
    setsockopt(static_cast<SOCKET>(fd_), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof(one));
    if (::bind(static_cast<SOCKET>(fd_), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        int e = WSAGetLastError();
        closesocket(static_cast<SOCKET>(fd_));
        fd_ = static_cast<poll_fd_t>(-1);
        throw std::runtime_error(std::string("bind failed: ") + std::to_string(e));
    }
#else
    ::setsockopt(static_cast<int>(fd_), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (::bind(static_cast<int>(fd_), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        int e = errno;
        ::close(static_cast<int>(fd_));
        fd_ = static_cast<poll_fd_t>(-1);
        throw std::runtime_error(std::string("bind: ") + std::strerror(e));
    }
#endif
}

void TcpListener::listen(int backlog) {
    if (fd_ == static_cast<poll_fd_t>(-1)) return;
#ifdef _WIN32
    if (::listen(static_cast<SOCKET>(fd_), backlog) != 0) {
        throw std::runtime_error("listen failed");
    }
#else
    if (::listen(static_cast<int>(fd_), backlog) < 0) {
        throw std::runtime_error(std::string("listen: ") + std::strerror(errno));
    }
#endif
}

void TcpListener::close() {
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

TcpSocket make_tcp_socket() {
    return TcpSocket(create_tcp_socket(), nullptr);
}

}  // namespace peimon
