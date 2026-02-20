#include "peimon/udp_socket.hpp"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <unistd.h>
#include <arpa/inet.h>

namespace peimon {

namespace {

int create_udp_socket() {
    int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        throw std::runtime_error(std::string("socket: ") + std::strerror(errno));
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return fd;
}

}  // namespace

void UdpSocket::bind(const char* host, std::uint16_t port) {
    if (fd_ >= 0) return;
    fd_ = create_udp_socket();
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host ? host : "0.0.0.0", &addr.sin_addr) <= 0) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("inet_pton failed");
    }
    int one = 1;
    ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        int e = errno;
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error(std::string("bind: ") + std::strerror(e));
    }
}

void UdpSocket::close() {
    if (fd_ >= 0) {
        if (loop_) loop_->unregister_fd(fd_);
        ::close(fd_);
        fd_ = -1;
        loop_ = nullptr;
    }
}

std::ptrdiff_t UdpSocket::recv_from(void* buf, std::size_t len, sockaddr* addr, socklen_t* addrlen) {
    if (fd_ < 0) return -1;
    ssize_t n = ::recvfrom(fd_, buf, len, 0, addr, addrlen);
    return static_cast<std::ptrdiff_t>(n);
}

std::ptrdiff_t UdpSocket::send_to(const void* buf, std::size_t len, const sockaddr* addr, socklen_t addrlen) {
    if (fd_ < 0) return -1;
    ssize_t n = ::sendto(fd_, buf, len, 0, addr, addrlen);
    return static_cast<std::ptrdiff_t>(n);
}

}  // namespace peimon
