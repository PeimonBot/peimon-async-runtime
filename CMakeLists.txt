cmake_minimum_required(VERSION 3.20)
project(peimon-async-runtime VERSION 0.1.0 LANGUAGES CXX DESCRIPTION "Minimal epoll event loop and fixed thread pool for Linux")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "peimon-async-runtime is Linux-only (epoll). Got: ${CMAKE_SYSTEM_NAME}")
endif()

# OpenSSL
find_package(OpenSSL REQUIRED)
# nghttp2 for HTTP/2 and ALPN selection
find_package(PkgConfig REQUIRED)
pkg_check_modules(nghttp2 REQUIRED libnghttp2)

# ngtcp2 and nghttp3 for QUIC/HTTP/3 (from third_party)
list(APPEND CMAKE_PREFIX_PATH "${CMAKE_CURRENT_SOURCE_DIR}/third_party")
find_package(ngtcp2 CONFIG REQUIRED)
find_package(nghttp3 CONFIG REQUIRED)

# Library
add_library(peimon_async_runtime
    src/event_loop.cpp
    src/epoll_poller.cpp
    src/thread_pool.cpp
    src/tcp_socket.cpp
    src/udp_socket.cpp
    src/tls_socket.cpp
    src/http_message.cpp
    src/http_server.cpp
    src/http3_server.cpp
)
target_include_directories(peimon_async_runtime
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(peimon_async_runtime PUBLIC
    OpenSSL::SSL OpenSSL::Crypto ${nghttp2_LIBRARIES}
    ngtcp2::ngtcp2_crypto_ossl ngtcp2::ngtcp2 nghttp3::nghttp3)
target_include_directories(peimon_async_runtime PRIVATE ${nghttp2_INCLUDE_DIRS})

# Self-signed cert for HTTPS demo (optional; run target generate_certs or create cert.pem/key.pem manually)
add_custom_target(generate_certs
    COMMAND openssl req -x509 -newkey rsa:2048
        -keyout "${CMAKE_CURRENT_BINARY_DIR}/key.pem"
        -out "${CMAKE_CURRENT_BINARY_DIR}/cert.pem"
        -days 365 -nodes -subj "/CN=localhost"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "Generating self-signed TLS cert and key for HTTPS demo"
)

# Demo executable (HTTPS Hello World server on port 8443; cert.pem/key.pem in build dir)
add_executable(peimon_demo examples/demo.cpp)
target_link_libraries(peimon_demo PRIVATE peimon_async_runtime)
add_dependencies(peimon_demo generate_certs)

# Minimal loop test
add_executable(test_loop_minimal examples/test_loop_minimal.cpp)
target_link_libraries(test_loop_minimal PRIVATE peimon_async_runtime)
