#include "peimon/udp_socket.hpp"
#include <cerrno>
#include <cstring>
#include <stdexcept>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
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

poll_fd_t create_udp_socket() {
#ifdef _WIN32
    ensure_winsock();
    SOCKET s = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET)
        throw std::runtime_error("socket failed");
    u_long nonblock = 1;
    if (ioctlsocket(s, FIONBIO, &nonblock) != 0) {
        closesocket(s);
        throw std::runtime_error("ioctlsocket FIONBIO failed");
    }
    return static_cast<poll_fd_t>(s);
#else
    int fd = ::socket(AF_INET,
#if defined(SOCK_CLOEXEC)
                      SOCK_DGRAM | SOCK_CLOEXEC,
#else
                      SOCK_DGRAM,
#endif
                      0);
    if (fd < 0)
        throw std::runtime_error(std::string("socket: ") + std::strerror(errno));
#if !defined(SOCK_CLOEXEC)
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

void UdpSocket::bind(const char* host, std::uint16_t port) {
    if (fd_ != static_cast<poll_fd_t>(-1)) return;
    fd_ = create_udp_socket();
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host ? host : "0.0.0.0", &addr.sin_addr) <= 0) {
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
        closesocket(static_cast<SOCKET>(fd_));
        fd_ = static_cast<poll_fd_t>(-1);
        throw std::runtime_error("bind failed");
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

void UdpSocket::close() {
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

std::ptrdiff_t UdpSocket::recv_from(void* buf, std::size_t len, sockaddr* addr, socklen_t* addrlen) {
    if (fd_ == static_cast<poll_fd_t>(-1)) return -1;
#ifdef _WIN32
    int n = recvfrom(static_cast<SOCKET>(fd_), static_cast<char*>(buf), static_cast<int>(len), 0, addr, addrlen);
    return static_cast<std::ptrdiff_t>(n);
#else
    ssize_t n = ::recvfrom(static_cast<int>(fd_), buf, len, 0, addr, addrlen);
    return static_cast<std::ptrdiff_t>(n);
#endif
}

std::ptrdiff_t UdpSocket::send_to(const void* buf, std::size_t len, const sockaddr* addr, socklen_t addrlen) {
    if (fd_ == static_cast<poll_fd_t>(-1)) return -1;
#ifdef _WIN32
    int n = sendto(static_cast<SOCKET>(fd_), static_cast<const char*>(buf), static_cast<int>(len), 0, addr, addrlen);
    return static_cast<std::ptrdiff_t>(n);
#else
    ssize_t n = ::sendto(static_cast<int>(fd_), buf, len, 0, addr, addrlen);
    return static_cast<std::ptrdiff_t>(n);
#endif
}

}  // namespace peimon
