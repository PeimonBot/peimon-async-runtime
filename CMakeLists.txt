cmake_minimum_required(VERSION 3.20)
project(peimon-async-runtime VERSION 0.1.0 LANGUAGES CXX DESCRIPTION "Async event loop (epoll/kqueue/IOCP) and thread pool for Linux, macOS, and Windows")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32 AND NOT APPLE AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "peimon-async-runtime supports Linux (epoll), macOS (kqueue), and Windows (IOCP). Got: ${CMAKE_SYSTEM_NAME}")
endif()

# Poller: epoll on Linux, kqueue on macOS, IOCP on Windows
if(WIN32)
    set(PEIMON_POLLER_SOURCES src/win_poller.cpp)
elseif(APPLE)
    set(PEIMON_POLLER_SOURCES src/kqueue_poller.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(PEIMON_POLLER_SOURCES src/epoll_poller.cpp)
endif()

# OpenSSL and nghttp2
find_package(OpenSSL REQUIRED)
if(WIN32)
    find_package(nghttp2 CONFIG REQUIRED)
    if(TARGET nghttp2::nghttp2)
        set(nghttp2_TARGET "nghttp2::nghttp2")
    elseif(TARGET unofficial::nghttp2::nghttp2)
        set(nghttp2_TARGET "unofficial::nghttp2::nghttp2")
    else()
        message(FATAL_ERROR "nghttp2 target not found. Expected nghttp2::nghttp2 or unofficial::nghttp2::nghttp2")
    endif()
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(nghttp2 REQUIRED libnghttp2)
    set(nghttp2_TARGET "${nghttp2_LIBRARIES}")
endif()

# ngtcp2 and nghttp3 for QUIC/HTTP/3 (from third_party) — Linux only; shared libs may be absent (gitignored)
set(PEIMON_BUILD_HTTP3 OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(_tp "${CMAKE_CURRENT_SOURCE_DIR}/third_party")
    if(EXISTS "${_tp}/lib/libngtcp2.so.16.7.3" AND EXISTS "${_tp}/lib/libngtcp2_crypto_ossl.so.0.1.1")
        list(APPEND CMAKE_PREFIX_PATH "${_tp}")
        find_package(ngtcp2 CONFIG QUIET)
        find_package(nghttp3 CONFIG QUIET)
        if(ngtcp2_FOUND AND nghttp3_FOUND)
            set(PEIMON_BUILD_HTTP3 ON)
        endif()
    endif()
    unset(_tp)
endif()

# Library sources (core + optional HTTP/3)
set(PEIMON_LIB_SOURCES
    src/event_loop.cpp
    ${PEIMON_POLLER_SOURCES}
    src/thread_pool.cpp
    src/tcp_socket.cpp
    src/udp_socket.cpp
    src/tls_socket.cpp
    src/http_message.cpp
    src/http_server.cpp
)
if(PEIMON_BUILD_HTTP3)
    list(APPEND PEIMON_LIB_SOURCES src/http3_server.cpp)
endif()

add_library(peimon_async_runtime ${PEIMON_LIB_SOURCES})
target_include_directories(peimon_async_runtime
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(peimon_async_runtime PUBLIC
    OpenSSL::SSL OpenSSL::Crypto ${nghttp2_TARGET}
)
if(WIN32)
    target_link_libraries(peimon_async_runtime PUBLIC ws2_32)
endif()
if(PEIMON_BUILD_HTTP3)
    target_link_libraries(peimon_async_runtime PUBLIC
        ngtcp2::ngtcp2_crypto_ossl ngtcp2::ngtcp2 nghttp3::nghttp3)
endif()
if(NOT WIN32)
    target_include_directories(peimon_async_runtime PRIVATE ${nghttp2_INCLUDE_DIRS})
endif()

# Self-signed cert for HTTPS demo (optional; run target generate_certs or create cert.pem/key.pem manually)
add_custom_target(generate_certs
    COMMAND openssl req -x509 -newkey rsa:2048
        -keyout "${CMAKE_CURRENT_BINARY_DIR}/key.pem"
        -out "${CMAKE_CURRENT_BINARY_DIR}/cert.pem"
        -days 365 -nodes -subj "/CN=localhost"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "Generating self-signed TLS cert and key for HTTPS demo"
)

# Demo executable (HTTP/1.1, HTTP/2, HTTP/3; requires ngtcp2/nghttp3)
if(PEIMON_BUILD_HTTP3)
    add_executable(peimon_demo examples/demo.cpp)
    target_link_libraries(peimon_demo PRIVATE peimon_async_runtime)
    add_dependencies(peimon_demo generate_certs)
endif()

# Minimal loop test (event loop + poller only; always built)
add_executable(test_loop_minimal examples/test_loop_minimal.cpp)
target_link_libraries(test_loop_minimal PRIVATE peimon_async_runtime)
