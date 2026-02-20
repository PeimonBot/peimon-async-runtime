#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace peimon {

/// HTTP/1.1 request method.
enum class HttpMethod : std::uint8_t {
    Get,
    Post,
    Head,
    Put,
    Delete,
    Options,
    Unknown,
};

/// Parsed HTTP/1.1 request (request line + headers + optional body).
struct HttpRequest {
    HttpMethod method{HttpMethod::Unknown};
    std::string path;
    std::string query;  // optional query string (without '?')
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;

    std::string_view header(std::string_view name) const;
};

/// Result of parsing: either a valid request or an error message.
struct HttpParseResult {
    bool ok{false};
    HttpRequest request;
    std::string error;  // if !ok, reason (e.g. "bad request")
};

/// HTTP/1.1 response (status line + headers + body) for building responses.
struct HttpResponse {
    int status_code{200};
    std::string status_phrase{"OK"};
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
};

/// Parse HTTP/1.1 request from a buffer (e.g. "GET /path HTTP/1.1\r\n...").
/// Handles \r\n line endings. Does not validate HTTP version strictly.
HttpParseResult parse_http_request(std::string_view data);

/// Build HTTP/1.1 response (status line + headers + body).
/// Content-Length is set from body.size() if not already present.
std::string make_http_response(int status_code,
                               std::string_view status_phrase,
                               std::vector<std::pair<std::string, std::string>> headers,
                               std::string_view body);

/// Convenience: 200 OK with body and optional Content-Type.
std::string make_http_ok(std::string_view body, std::string_view content_type = "text/plain");

/// Convenience: 404 Not Found.
std::string make_http_not_found(std::string_view body = "Not Found");

/// Convenience: 400 Bad Request.
std::string make_http_bad_request(std::string_view body = "Bad Request");

/// Serialize HttpResponse to HTTP/1.1 wire format (adds Content-Length if missing).
std::string to_string(const HttpResponse& resp);

}  // namespace peimon
