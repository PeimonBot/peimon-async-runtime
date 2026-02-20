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

# On macOS, help find nghttp2 via Homebrew (brew --prefix nghttp2 or libnghttp2)
if(APPLE)
    set(_brew_nghttp2 "")
    set(_brew_libnghttp2 "")
    execute_process(COMMAND brew --prefix nghttp2 OUTPUT_VARIABLE _brew_nghttp2 OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    execute_process(COMMAND brew --prefix libnghttp2 OUTPUT_VARIABLE _brew_libnghttp2 OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
    if(_brew_nghttp2)
        list(APPEND CMAKE_PREFIX_PATH "${_brew_nghttp2}")
        set(ENV{PKG_CONFIG_PATH} "${_brew_nghttp2}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    endif()
    if(_brew_libnghttp2)
        list(APPEND CMAKE_PREFIX_PATH "${_brew_libnghttp2}")
        set(ENV{PKG_CONFIG_PATH} "${_brew_libnghttp2}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
    endif()
endif()

# OpenSSL and nghttp2
find_package(OpenSSL REQUIRED)
if(WIN32)
    # Try CONFIG first (vcpkg or other CMake package provider)
    find_package(nghttp2 CONFIG QUIET)
    if(TARGET nghttp2::nghttp2)
        set(nghttp2_TARGET "nghttp2::nghttp2")
    elseif(TARGET unofficial::nghttp2::nghttp2)
        set(nghttp2_TARGET "unofficial::nghttp2::nghttp2")
    endif()
    # Fallback: pkg_check_modules if PkgConfig is available (e.g. with vcpkg pkgconfig)
    if(NOT nghttp2_TARGET)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(nghttp2 QUIET libnghttp2)
            if(nghttp2_FOUND)
                set(nghttp2_TARGET "${nghttp2_LIBRARIES}")
                set(nghttp2_INCLUDE_DIRS "${nghttp2_INCLUDE_DIRS}")
                set(nghttp2_LIBRARY_DIRS "${nghttp2_LIBRARY_DIRS}")
            endif()
        endif()
    endif()
    # Fallback: look for nghttp2.lib in vcpkg install directory (manifest: build/vcpkg_installed; classic: vcpkg/installed)
    if(NOT nghttp2_TARGET AND CMAKE_TOOLCHAIN_FILE)
        if(NOT DEFINED VCPKG_TARGET_TRIPLET)
            set(VCPKG_TARGET_TRIPLET "$ENV{VCPKG_DEFAULT_TRIPLET}")
        endif()
        if(NOT VCPKG_TARGET_TRIPLET)
            set(VCPKG_TARGET_TRIPLET "x64-windows")
        endif()
        set(_vcpkg_search_paths
            "${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}"
        )
        get_filename_component(_vcpkg_scripts "${CMAKE_TOOLCHAIN_FILE}" DIRECTORY)
        get_filename_component(_vcpkg_root "${_vcpkg_scripts}/../.." ABSOLUTE)
        list(APPEND _vcpkg_search_paths "${_vcpkg_root}/installed/${VCPKG_TARGET_TRIPLET}")
        find_library(NGHTTP2_LIBRARY NAMES nghttp2 PATHS ${_vcpkg_search_paths} PATH_SUFFIXES lib NO_DEFAULT_PATH)
        find_path(NGHTTP2_INCLUDE_DIR NAMES nghttp2/nghttp2.h PATHS ${_vcpkg_search_paths} PATH_SUFFIXES include NO_DEFAULT_PATH)
        if(NGHTTP2_LIBRARY AND NGHTTP2_INCLUDE_DIR)
            add_library(nghttp2_vcpkg_fallback UNKNOWN IMPORTED)
            set_target_properties(nghttp2_vcpkg_fallback PROPERTIES
                IMPORTED_LOCATION "${NGHTTP2_LIBRARY}"
                INTERFACE_INCLUDE_DIRECTORIES "${NGHTTP2_INCLUDE_DIR}"
            )
            set(nghttp2_TARGET "nghttp2_vcpkg_fallback")
        endif()
    endif()
    if(NOT nghttp2_TARGET)
        message(FATAL_ERROR "nghttp2 not found. Try: find_package(nghttp2 CONFIG), pkg_check_modules(libnghttp2), or ensure vcpkg manifest includes nghttp2 and CMAKE_TOOLCHAIN_FILE points to vcpkg.cmake")
    endif()
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(nghttp2 REQUIRED libnghttp2)
    if(APPLE AND _brew_libnghttp2)
        find_library(NGHTTP2_LIBRARY NAMES nghttp2 PATHS "${_brew_libnghttp2}/lib" NO_DEFAULT_PATH)
        if(NGHTTP2_LIBRARY)
            set(nghttp2_TARGET "${NGHTTP2_LIBRARY}")
        else()
            set(nghttp2_TARGET "${nghttp2_LIBRARIES}")
        endif()
    else()
        set(nghttp2_TARGET "${nghttp2_LIBRARIES}")
    endif()
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
    # Static nghttp2 (vcpkg default): avoid __declspec(dllimport) so symbols link correctly
    target_compile_definitions(peimon_async_runtime PUBLIC NGHTTP2_STATICLIB)
endif()
if(PEIMON_BUILD_HTTP3)
    target_link_libraries(peimon_async_runtime PUBLIC
        ngtcp2::ngtcp2_crypto_ossl ngtcp2::ngtcp2 nghttp3::nghttp3)
endif()
if(NOT WIN32)
    target_include_directories(peimon_async_runtime PRIVATE ${nghttp2_INCLUDE_DIRS})
    target_link_directories(peimon_async_runtime PRIVATE ${nghttp2_LIBRARY_DIRS})
else()
    if(nghttp2_INCLUDE_DIRS)
        target_include_directories(peimon_async_runtime PRIVATE ${nghttp2_INCLUDE_DIRS})
    endif()
    # Explicitly add vcpkg include directory for MSVC when find_package does not propagate it
    if(MSVC AND CMAKE_TOOLCHAIN_FILE)
        if(NOT DEFINED VCPKG_TARGET_TRIPLET)
            set(VCPKG_TARGET_TRIPLET "$ENV{VCPKG_DEFAULT_TRIPLET}")
        endif()
        if(NOT VCPKG_TARGET_TRIPLET)
            set(VCPKG_TARGET_TRIPLET "x64-windows")
        endif()
        set(_vcpkg_include_manifest "${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/include")
        get_filename_component(_vcpkg_scripts "${CMAKE_TOOLCHAIN_FILE}" DIRECTORY)
        get_filename_component(_vcpkg_root "${_vcpkg_scripts}/../.." ABSOLUTE)
        set(_vcpkg_include_classic "${_vcpkg_root}/installed/${VCPKG_TARGET_TRIPLET}/include")
        if(EXISTS "${_vcpkg_include_manifest}")
            target_include_directories(peimon_async_runtime PRIVATE "${_vcpkg_include_manifest}")
        elseif(EXISTS "${_vcpkg_include_classic}")
            target_include_directories(peimon_async_runtime PRIVATE "${_vcpkg_include_classic}")
        endif()
    endif()
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
