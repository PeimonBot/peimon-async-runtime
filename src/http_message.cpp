#include "peimon/http_message.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace peimon {

namespace {

bool iequal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    return std::ranges::equal(a, b, [](char x, char y) {
        return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
    });
}

std::string_view trim_cr(std::string_view s) {
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) s.remove_suffix(1);
    return s;
}

}  // namespace

std::string_view HttpRequest::header(std::string_view name) const {
    for (const auto& [k, v] : headers) {
        if (iequal(k, name)) return v;
    }
    return {};
}

HttpParseResult parse_http_request(std::string_view data) {
    HttpParseResult result;
    result.ok = false;

    auto rest = data;
    auto next_line = [&rest]() -> std::string_view {
        auto pos = rest.find("\r\n");
        if (pos == std::string_view::npos) pos = rest.find('\n');
        if (pos == std::string_view::npos) return {};
        std::string_view line = rest.substr(0, pos);
        rest = (pos + 2 <= rest.size() && rest.substr(pos, 2) == "\r\n")
                   ? rest.substr(pos + 2)
                   : rest.substr(pos + 1);
        return line;
    };

    std::string_view request_line = next_line();
    if (request_line.empty()) {
        result.error = "empty request line";
        return result;
    }

    // Request line: METHOD SP Request-URI SP HTTP/1.x
    std::size_t sp1 = request_line.find(' ');
    if (sp1 == std::string_view::npos) {
        result.error = "bad request line";
        return result;
    }
    std::string_view method_sv = request_line.substr(0, sp1);
    std::size_t sp2 = request_line.find(' ', sp1 + 1);
    if (sp2 == std::string_view::npos) {
        result.error = "bad request line";
        return result;
    }
    std::string_view uri = request_line.substr(sp1 + 1, sp2 - sp1 - 1);

    if (iequal(method_sv, "GET")) result.request.method = HttpMethod::Get;
    else if (iequal(method_sv, "POST")) result.request.method = HttpMethod::Post;
    else if (iequal(method_sv, "HEAD")) result.request.method = HttpMethod::Head;
    else if (iequal(method_sv, "PUT")) result.request.method = HttpMethod::Put;
    else if (iequal(method_sv, "DELETE")) result.request.method = HttpMethod::Delete;
    else if (iequal(method_sv, "OPTIONS")) result.request.method = HttpMethod::Options;
    else result.request.method = HttpMethod::Unknown;

    std::size_t q = uri.find('?');
    if (q != std::string_view::npos) {
        result.request.path = std::string(uri.substr(0, q));
        result.request.query = std::string(uri.substr(q + 1));
    } else {
        result.request.path = std::string(uri);
    }

    // Headers
    for (;;) {
        std::string_view line = next_line();
        if (line.empty()) break;
        std::size_t colon = line.find(':');
        if (colon == std::string_view::npos) continue;
        std::string name(line.substr(0, colon));
        std::string_view value_sv = trim_cr(line.substr(colon + 1));
        while (!value_sv.empty() && value_sv.front() == ' ') value_sv.remove_prefix(1);
        result.request.headers.emplace_back(std::move(name), std::string(value_sv));
    }

    // Body: everything after \r\n\r\n
    result.request.body = std::string(rest);
    result.ok = true;
    return result;
}

std::string make_http_response(int status_code,
                               std::string_view status_phrase,
                               std::vector<std::pair<std::string, std::string>> headers,
                               std::string_view body) {
    std::ostringstream out;
    out << "HTTP/1.1 " << status_code << ' ' << status_phrase << "\r\n";

    bool has_content_length = false;
    for (const auto& [k, v] : headers) {
        if (iequal(k, "Content-Length")) has_content_length = true;
        out << k << ": " << v << "\r\n";
    }
    if (!has_content_length)
        out << "Content-Length: " << body.size() << "\r\n";
    out << "\r\n";
    out << body;
    return out.str();
}

std::string make_http_ok(std::string_view body, std::string_view content_type) {
    std::vector<std::pair<std::string, std::string>> headers;
    headers.emplace_back("Content-Type", std::string(content_type));
    return make_http_response(200, "OK", std::move(headers), body);
}

std::string make_http_not_found(std::string_view body) {
    std::vector<std::pair<std::string, std::string>> headers;
    headers.emplace_back("Content-Type", "text/plain");
    return make_http_response(404, "Not Found", std::move(headers), body);
}

std::string make_http_bad_request(std::string_view body) {
    std::vector<std::pair<std::string, std::string>> headers;
    headers.emplace_back("Content-Type", "text/plain");
    return make_http_response(400, "Bad Request", std::move(headers), body);
}

std::string to_string(const HttpResponse& resp) {
    return make_http_response(resp.status_code, resp.status_phrase, resp.headers, resp.body);
}

}  // namespace peimon
