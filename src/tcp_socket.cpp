#include "peimon/tcp_socket.hpp"
#include <stdexcept>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace peimon {

namespace {

int create_tcp_socket() {
    int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        throw std::runtime_error(std::string("socket: ") + std::strerror(errno));
    }
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return fd;
}

}  // namespace

void TcpListener::bind(const char* host, std::uint16_t port) {
    if (fd_ >= 0) return;
    fd_ = create_tcp_socket();
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
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

void TcpListener::listen(int backlog) {
    if (fd_ < 0) return;
    if (::listen(fd_, backlog) < 0) {
        throw std::runtime_error(std::string("listen: ") + std::strerror(errno));
    }
}

void TcpListener::close() {
    if (fd_ >= 0) {
        if (loop_) loop_->unregister_fd(fd_);
        ::close(fd_);
        fd_ = -1;
        loop_ = nullptr;
    }
}

TcpSocket make_tcp_socket() {
    return TcpSocket(create_tcp_socket(), nullptr);
}

}  // namespace peimon
