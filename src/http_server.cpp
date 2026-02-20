#include "peimon/http_server.hpp"
#include "peimon/http_message.hpp"
#include "peimon/tcp_socket.hpp"
#include "peimon/tls_socket.hpp"
// Include before nghttp2 for MSVC (nghttp2.h uses uint8_t, size_t; avoid ssize_t)
#include <cstddef>
#include <cstdint>
#ifdef _WIN32
#define NGHTTP2_NO_SSIZE_T
#endif
#include <nghttp2/nghttp2.h>
#if defined(__linux__)
// Some Linux distros' libnghttp2 headers do not expose nghttp2_ssize
#include <sys/types.h>
using nghttp2_ssize = ssize_t;
#endif
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <map>
#include <stdexcept>
#include <iostream>

namespace peimon {

namespace {

// ----- HTTP/2 helpers (ALPN-selected h2) -----
struct H2StreamReq {
    HttpRequest request;
};
struct H2StreamBody {
    std::string body;
    std::size_t offset{0};
};
struct H2UserData {
    std::string send_buf;
    EventLoop* loop{nullptr};
    const HttpHandler* handler{nullptr};
    std::map<int32_t, H2StreamReq> stream_requests;
    std::map<int32_t, H2StreamBody> stream_bodies;
};

static nghttp2_ssize h2_send_cb(nghttp2_session* session, const uint8_t* data,
                                std::size_t length, int /*flags*/, void* user_data) {
    auto* ud = static_cast<H2UserData*>(user_data);
    ud->send_buf.append(reinterpret_cast<const char*>(data), length);
    return static_cast<nghttp2_ssize>(length);
}

static int h2_on_header(nghttp2_session* /*session*/, const nghttp2_frame* frame,
                        const uint8_t* name, std::size_t namelen,
                        const uint8_t* value, std::size_t valuelen,
                        uint8_t /*flags*/, void* user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    auto* ud = static_cast<H2UserData*>(user_data);
    auto& req = ud->stream_requests[frame->hd.stream_id].request;
    std::string_view n(reinterpret_cast<const char*>(name), namelen),
                     v(reinterpret_cast<const char*>(value), valuelen);
    if (n == ":method") {
        if (v == "GET") req.method = HttpMethod::Get;
        else if (v == "POST") req.method = HttpMethod::Post;
        else if (v == "HEAD") req.method = HttpMethod::Head;
        else if (v == "PUT") req.method = HttpMethod::Put;
        else if (v == "DELETE") req.method = HttpMethod::Delete;
        else if (v == "OPTIONS") req.method = HttpMethod::Options;
        else req.method = HttpMethod::Unknown;
    } else if (n == ":path") {
        std::string pathv(v);
        std::size_t q = pathv.find('?');
        if (q != std::string::npos) {
            req.path = pathv.substr(0, q);
            req.query = pathv.substr(q + 1);
        } else {
            req.path = std::move(pathv);
        }
    } else if (n != ":scheme" && n != ":authority") {
        req.headers.emplace_back(std::string(n), std::string(v));
    }
    return 0;
}

static nghttp2_ssize h2_data_read_cb(nghttp2_session* /*session*/, int32_t /*stream_id*/,
                                     uint8_t* buf, std::size_t length,
                                     uint32_t* data_flags, nghttp2_data_source* source,
                                     void* /*user_data*/) {
    auto* sb = static_cast<H2StreamBody*>(source->ptr);
    if (!sb || sb->offset >= sb->body.size()) {
        *data_flags = NGHTTP2_DATA_FLAG_EOF;
        return 0;
    }
    std::size_t to_copy = (std::min)(length, sb->body.size() - sb->offset);
    std::memcpy(buf, sb->body.data() + sb->offset, to_copy);
    sb->offset += to_copy;
    if (sb->offset >= sb->body.size())
        *data_flags = NGHTTP2_DATA_FLAG_EOF;
    return static_cast<nghttp2_ssize>(to_copy);
}

static int h2_on_frame_recv(nghttp2_session* session, const nghttp2_frame* frame,
                           void* user_data) {
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    auto* ud = static_cast<H2UserData*>(user_data);
    auto it = ud->stream_requests.find(frame->hd.stream_id);
    if (it == ud->stream_requests.end() || !ud->handler) return 0;
    const HttpRequest& req = it->second.request;
    std::string body = (*ud->handler)(req);
    if (body.size() >= 9 && body.substr(0, 9) == "HTTP/1.1 ")
        body.clear();  // handler returned raw response; treat as empty and use 200
    if (body.empty())
        body = make_http_ok("");  // minimal 200
    else if (body.size() < 9 || body.substr(0, 9) != "HTTP/1.1 ")
        body = make_http_ok(body, "text/html; charset=utf-8");

    // Parse status and headers from HTTP/1.1-style response for H2 response
    std::string_view rest(body);
    auto crlf = rest.find("\r\n");
    if (crlf == std::string_view::npos) crlf = rest.size();
    std::string_view status_line = rest.substr(0, crlf);
    rest = crlf + 2 <= rest.size() ? rest.substr(crlf + 2) : std::string_view{};
    std::string resp_body;
    std::vector<std::pair<std::string, std::string>> resp_headers;
    int status = 200;
    while (!rest.empty()) {
        auto line_end = rest.find("\r\n");
        if (line_end == std::string_view::npos) line_end = rest.size();
        std::string_view line = rest.substr(0, line_end);
        rest = line_end + 2 <= rest.size() ? rest.substr(line_end + 2) : std::string_view{};
        if (line.empty()) { resp_body = std::string(rest); break; }
        if (line.substr(0, 8) == "HTTP/1.1 ") {
            auto sp = line.find(' ', 9);
            if (sp != std::string_view::npos) {
                char* end = nullptr;
                status = static_cast<int>(std::strtol(line.data() + 9, &end, 10));
            }
            continue;
        }
        auto colon = line.find(':');
        if (colon != std::string_view::npos) {
            std::string hname(line.substr(0, colon));
            std::string_view v = line.substr(colon + 1);
            while (!v.empty() && v.front() == ' ') v.remove_prefix(1);
            auto eq = [](std::string_view a, const char* b) {
            std::size_t blen = std::strlen(b);
            if (a.size() != blen) return false;
            for (std::size_t i = 0; i < blen; ++i)
                if (std::tolower(static_cast<unsigned char>(a[i])) != static_cast<unsigned char>(b[i])) return false;
            return true;
        };
        if (eq(std::string_view(hname), "content-length")) continue;
            resp_headers.emplace_back(std::move(hname), std::string(v));
        }
    }
    if (resp_body.empty() && body.size() > status_line.size() + 2) {
        auto body_start = body.find("\r\n\r\n");
        if (body_start != std::string::npos)
            resp_body = body.substr(body_start + 4);
    }

    std::string status_str = std::to_string(status);
    const uint8_t status_name[] = ":status";
    const uint8_t ct_name[] = "content-type";
    const uint8_t ct_value[] = "text/html; charset=utf-8";
    nghttp2_nv nva[] = {
        {const_cast<uint8_t*>(status_name), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(status_str.c_str())), 7, status_str.size(), NGHTTP2_NV_FLAG_NONE},
        {const_cast<uint8_t*>(ct_name), const_cast<uint8_t*>(ct_value), 12, 23, NGHTTP2_NV_FLAG_NONE},
    };
    if (!resp_body.empty()) {
        ud->stream_bodies[frame->hd.stream_id].body = std::move(resp_body);
        ud->stream_bodies[frame->hd.stream_id].offset = 0;
        nghttp2_data_provider prd;
        prd.source.ptr = &ud->stream_bodies[frame->hd.stream_id];
        prd.read_callback = h2_data_read_cb;
        nghttp2_submit_response(session, frame->hd.stream_id, nva, 2, &prd);
    } else {
        nghttp2_submit_response(session, frame->hd.stream_id, nva, 2, nullptr);
    }
    return 0;
}

template <typename SocketT>
Task<void> handle_connection_impl(EventLoop& loop, SocketT socket, const HttpHandler& handler) {
    std::string buf;
    buf.reserve(8192);
    constexpr std::size_t chunk = 4096;
    char tmp[chunk];

    for (;;) {
        std::ptrdiff_t n = co_await socket.async_read(loop, tmp, chunk);
        if (n <= 0) break;
        buf.append(tmp, static_cast<std::size_t>(n));
        if (buf.find("\r\n\r\n") != std::string::npos) break;
        if (buf.size() > 64 * 1024) break;  // limit header size
    }

    if (buf.empty()) {
        socket.close();
        co_return;
    }

    HttpParseResult parse = parse_http_request(buf);
    if (!parse.ok) {
        std::string resp = make_http_bad_request(parse.error);
        co_await socket.async_write(loop, resp.data(), resp.size());
        socket.close();
        co_return;
    }

    std::size_t content_length = 0;
    if (auto cl = parse.request.header("Content-Length"); !cl.empty()) {
        char* end = nullptr;
        unsigned long v = std::strtoul(cl.data(), &end, 10);
        if (end != cl.data()) content_length = static_cast<std::size_t>(v);
    }
    if (content_length > 1024 * 1024) content_length = 0;  // cap 1MB

    while (parse.request.body.size() < content_length) {
        std::size_t to_read = (std::min)(chunk, content_length - parse.request.body.size());
        std::ptrdiff_t n = co_await socket.async_read(loop, tmp, to_read);
        if (n <= 0) break;
        parse.request.body.append(tmp, static_cast<std::size_t>(n));
    }

    std::string response = handler(parse.request);
    if (response.size() < 9 || response.substr(0, 9) != "HTTP/1.1 ")
        response = make_http_ok(response);

    std::size_t sent = 0;
    while (sent < response.size()) {
        std::ptrdiff_t n = co_await socket.async_write(loop, response.data() + sent, response.size() - sent);
        if (n <= 0) break;
        sent += static_cast<std::size_t>(n);
    }

    socket.close();
}

Task<void> handle_h2_connection(EventLoop& loop, TlsSocket socket, const HttpHandler& handler) {
    H2UserData ud;
    ud.loop = &loop;
    ud.handler = &handler;

    nghttp2_session_callbacks* cbs = nullptr;
    if (nghttp2_session_callbacks_new(&cbs) != 0) { socket.close(); co_return; }
    nghttp2_session_callbacks_set_send_callback(cbs, h2_send_cb);
    nghttp2_session_callbacks_set_on_header_callback(cbs, h2_on_header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, h2_on_frame_recv);

    nghttp2_session* session = nullptr;
    if (nghttp2_session_server_new(&session, cbs, &ud) != 0) {
        nghttp2_session_callbacks_del(cbs);
        socket.close();
        co_return;
    }
    nghttp2_session_callbacks_del(cbs);

    constexpr std::size_t chunk = 4096;
    std::string read_buf;
    read_buf.reserve(8192);
    char tmp[chunk];

    for (;;) {
        std::ptrdiff_t n = co_await socket.async_read(loop, tmp, chunk);
        if (n <= 0) break;
        read_buf.append(tmp, static_cast<std::size_t>(n));
        nghttp2_ssize consumed = nghttp2_session_mem_recv(session,
            reinterpret_cast<const uint8_t*>(read_buf.data()), read_buf.size());
        if (consumed < 0) break;
        if (consumed > 0) {
            read_buf.erase(0, static_cast<std::size_t>(consumed));
            int r = nghttp2_session_send(session);
            if (r != 0) break;
            std::size_t sent = 0;
            while (sent < ud.send_buf.size()) {
                std::ptrdiff_t wn = co_await socket.async_write(loop, ud.send_buf.data() + sent, ud.send_buf.size() - sent);
                if (wn <= 0) break;
                sent += static_cast<std::size_t>(wn);
            }
            if (sent > 0) ud.send_buf.erase(0, sent);
        }
    }

    nghttp2_session_del(session);
    socket.close();
}

}  // namespace

Task<void> run_http_server(EventLoop& loop, HttpServerOptions options) {
    if (!options.handler) {
        std::cerr << "http_server: no handler set\n";
        co_return;
    }

    Acceptor acceptor;
    acceptor.bind(options.host, options.port);
    acceptor.listen(128);

    TlsContext tls_ctx;
    if (options.use_tls) {
        if (!options.cert_file || !options.key_file) {
            std::cerr << "http_server: TLS requested but cert_file or key_file missing\n";
            co_return;
        }
        tls_ctx = make_tls_server_context(options.cert_file, options.key_file);
        if (!tls_ctx) {
            std::cerr << "http_server: failed to create TLS context (check cert/key files)\n";
            co_return;
        }
    }

    std::cout << "HTTP" << (options.use_tls ? "S" : "") << " server listening on " << options.host
              << ":" << options.port << std::endl;

    while (loop.running()) {
        Socket client = co_await acceptor.async_accept(loop);
        if (!client.is_open()) break;

        if (options.use_tls) {
            SSL* ssl = SSL_new(tls_ctx.get());
            if (!ssl) {
                client.close();
                continue;
            }
            SSL_set_fd(ssl, static_cast<int>(client.fd()));
            TlsSocket tls(std::move(client), ssl);
            std::error_code err = co_await tls.async_handshake_server(loop);
            if (err) {
                tls.close();
                continue;
            }
            if (tls.is_http2_negotiated()) {
                Task<void> t = handle_h2_connection(loop, std::move(tls), options.handler);
                t.start(loop);
            } else {
                Task<void> t = handle_connection_impl(loop, std::move(tls), options.handler);
                t.start(loop);
            }
        } else {
            Task<void> t = handle_connection_impl(loop, std::move(client), options.handler);
            t.start(loop);
        }
    }

    acceptor.close();
}

}  // namespace peimon
