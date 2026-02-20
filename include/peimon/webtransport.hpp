#pragma once

// WebTransport over HTTP/3 constants and capsule protocol (RFC 9297, draft-ietf-webtrans-http3).
// C++23.

#include <cstdint>
#include <utility>

namespace peimon {

// Unidirectional WebTransport stream type (draft-ietf-webtrans-http3).
constexpr std::uint8_t WT_STREAM_TYPE_UNI = 0x54u;

// Bidirectional WebTransport stream signal value (first bytes on stream).
constexpr std::uint8_t WT_STREAM_SIGNAL_BIDI = 0x41u;

// Capsule types (RFC 9297).
constexpr std::uint64_t CAPSULE_TYPE_DATAGRAM = 0x00u;
constexpr std::uint64_t CAPSULE_TYPE_WT_DRAIN_SESSION = 0x78aeu;

/// Encodes a QUIC varint into buf; returns number of bytes written (1, 2, 4, or 8).
inline std::size_t encode_varint(std::uint8_t* buf, std::uint64_t value) {
    if (value < 64u) {
        buf[0] = static_cast<std::uint8_t>(value);
        return 1;
    }
    if (value < 16384u) {
        buf[0] = static_cast<std::uint8_t>((value >> 8) | 0x40u);
        buf[1] = static_cast<std::uint8_t>(value & 0xffu);
        return 2;
    }
    if (value < 1073741824u) {
        buf[0] = static_cast<std::uint8_t>((value >> 16) | 0x80u);
        buf[1] = static_cast<std::uint8_t>((value >> 8) & 0xffu);
        buf[2] = static_cast<std::uint8_t>(value & 0xffu);
        return 4;
    }
    buf[0] = 0xc0u;
    buf[1] = static_cast<std::uint8_t>((value >> 48) & 0xffu);
    buf[2] = static_cast<std::uint8_t>((value >> 40) & 0xffu);
    buf[3] = static_cast<std::uint8_t>((value >> 32) & 0xffu);
    buf[4] = static_cast<std::uint8_t>((value >> 24) & 0xffu);
    buf[5] = static_cast<std::uint8_t>((value >> 16) & 0xffu);
    buf[6] = static_cast<std::uint8_t>((value >> 8) & 0xffu);
    buf[7] = static_cast<std::uint8_t>(value & 0xffu);
    return 8;
}

/// Decodes a QUIC varint from [ptr, end). Returns {value, bytes_consumed} or {0, 0} on error.
inline std::pair<std::uint64_t, std::size_t> decode_varint(const std::uint8_t* ptr, const std::uint8_t* end) {
    if (ptr == end) return {0, 0};
    std::uint8_t b = *ptr++;
    if ((b & 0xc0u) == 0u) {
        return {static_cast<std::uint64_t>(b & 0x3fu), 1};
    }
    if ((b & 0xe0u) == 0x40u) {
        if (ptr + 1 > end) return {0, 0};
        return {static_cast<std::uint64_t>((static_cast<std::uint64_t>(b & 0x1fu) << 8) | *ptr), 2};
    }
    if ((b & 0xf0u) == 0x80u) {
        if (ptr + 3 > end) return {0, 0};
        return {static_cast<std::uint64_t>((static_cast<std::uint64_t>(b & 0x0fu) << 24) |
                                           (static_cast<std::uint64_t>(ptr[0]) << 16) |
                                           (static_cast<std::uint64_t>(ptr[1]) << 8) |
                                           ptr[2]), 4};
    }
    if ((b & 0xfcu) == 0xc0u) {
        if (ptr + 7 > end) return {0, 0};
        return {static_cast<std::uint64_t>((static_cast<std::uint64_t>(b & 0x03u) << 56) |
                                           (static_cast<std::uint64_t>(ptr[0]) << 48) |
                                           (static_cast<std::uint64_t>(ptr[1]) << 40) |
                                           (static_cast<std::uint64_t>(ptr[2]) << 32) |
                                           (static_cast<std::uint64_t>(ptr[3]) << 24) |
                                           (static_cast<std::uint64_t>(ptr[4]) << 16) |
                                           (static_cast<std::uint64_t>(ptr[5]) << 8) |
                                           ptr[6]), 8};
    }
    return {0, 0};
}

/// HTTP/3 datagram: quarter stream ID (varint) + payload. Session ID = quarter_stream_id * 4.
constexpr std::uint64_t quarter_stream_id_to_session_id(std::uint64_t quarter) {
    return quarter * 4u;
}
constexpr std::uint64_t session_id_to_quarter_stream_id(std::uint64_t session_id) {
    return session_id / 4u;
}

}  // namespace peimon
