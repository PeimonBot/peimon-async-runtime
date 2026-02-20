// HTTP/3 (QUIC) server: UDP socket + ngtcp2 transport + nghttp3 application layer.
// WebTransport over HTTP/3 (Capsule protocol, bidi/uni streams, datagrams). C++23.

#include "peimon/http3_server.hpp"
#include "peimon/http_message.hpp"
#include "peimon/udp_socket.hpp"
#include "peimon/webtransport.hpp"
#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <array>
#include <chrono>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace peimon {

namespace {

constexpr std::size_t NGTCP2_SV_SCIDLEN = 18;
constexpr std::size_t MAX_UDP_PAYLOAD = 1452;
constexpr std::size_t MAX_PKT_BUF = 65536;

// Hash and equality for ngtcp2_cid to use as map key.
struct CidHash {
    std::size_t operator()(const ngtcp2_cid& c) const noexcept {
        std::size_t h = c.datalen;
        for (size_t i = 0; i < c.datalen && i < NGTCP2_MAX_CIDLEN; ++i)
            h = h * 31u + static_cast<unsigned char>(c.data[i]);
        return h;
    }
};
struct CidEqual {
    bool operator()(const ngtcp2_cid& a, const ngtcp2_cid& b) const noexcept {
        return ngtcp2_cid_eq(&a, &b) != 0;
    }
};

struct QuicConn;
struct Http3ServerState;

static void schedule_conn_timer(Http3ServerState* state, std::shared_ptr<QuicConn> conn);
static void flush_send_quic(Http3ServerState* state, QuicConn* q);

static int h3_begin_headers(nghttp3_conn*, int64_t, void*, void*);
static int h3_recv_header(nghttp3_conn*, int64_t, int32_t, nghttp3_rcbuf*, nghttp3_rcbuf*, uint8_t, void*, void*);
static int h3_end_headers(nghttp3_conn*, int64_t, int, void*, void*);
static nghttp3_ssize h3_read_data(nghttp3_conn*, int64_t, nghttp3_vec*, size_t, uint32_t*, void*, void*);
static int h3_end_stream(nghttp3_conn*, int64_t, void*, void*);
static int h3_recv_data(nghttp3_conn*, int64_t, const uint8_t*, size_t, void*, void*);
static int h3_deferred_consume(nghttp3_conn*, int64_t, size_t, void*, void*);
static int h3_stream_close(nghttp3_conn*, int64_t, uint64_t, void*, void*);
static int h3_stop_sending(nghttp3_conn*, int64_t, uint64_t, void*, void*);
static int h3_reset_stream(nghttp3_conn*, int64_t, uint64_t, void*, void*);
static int h3_acked_stream_data(nghttp3_conn*, int64_t, uint64_t, void*, void*);

static void on_wt_datagram_echo(Http3ServerState* state, QuicConn* q,
    std::uint64_t quarter_stream_id, const std::uint8_t* payload, std::size_t payloadlen);
static void on_wt_stream_echo_bidi(QuicConn* q, int64_t client_stream_id,
    const std::uint8_t* data, std::size_t datalen, int fin);
static void on_wt_stream_echo_uni(QuicConn* q, int64_t client_stream_id,
    std::uint64_t session_id, const std::uint8_t* data, std::size_t datalen, int fin);

// Per-stream state for building HttpRequest from HTTP/3 headers.
struct H3StreamReq {
    HttpRequest request;
    bool is_webtransport_connect{false};
};

// Pending echo: datagram payload to send back as capsule on CONNECT stream.
struct PendingCapsuleEcho {
    std::string payload;
};

struct QuicConn {
    ngtcp2_conn* conn{nullptr};
    ngtcp2_path_storage path_storage{};
    ngtcp2_crypto_ossl_ctx* ossl_ctx{nullptr};
    SSL* ssl{nullptr};
    ngtcp2_crypto_conn_ref conn_ref{};
    Http3ServerState* server{nullptr};
    bool timer_scheduled{false};

    nghttp3_conn* h3_conn{nullptr};
    bool h3_ready{false};  // true after we've sent stream type bytes and bound control/qpack streams
    std::uint8_t pending_stream_types[3]{0x00, 0x02, 0x03};  // control, qpack enc, qpack dec
    std::int64_t pending_stream_ids[3]{3, 7, 11};
    std::size_t pending_stream_idx{0};
    std::map<int64_t, H3StreamReq> stream_requests;
    std::map<int64_t, std::string> stream_response_bodies;

    // WebTransport: CONNECT stream id (-1 if none), pending capsule echos, stream classification.
    int64_t wt_session_stream_id{-1};
    std::vector<PendingCapsuleEcho> pending_capsule_echos;
    std::unordered_set<int64_t> wt_bidi_streams;   // client bidi we handle as WebTransport
    std::unordered_set<int64_t> wt_uni_streams;     // client uni we handle as WebTransport
    std::map<int64_t, int64_t> wt_client_to_server_bidi;  // client stream_id -> server bidi stream_id
    std::map<int64_t, uint64_t> wt_uni_session;           // client uni stream_id -> session_id (varint)
    std::map<int64_t, int64_t> wt_uni_client_to_server;   // client uni -> server uni stream_id
    int64_t next_server_uni_stream_id{15};
    int64_t next_server_bidi_stream_id{1};
    std::map<int64_t, std::string> stream_read_buffer;   // client stream_id -> buffered bytes before classify
    struct PendingStreamWrite { int64_t stream_id; std::string data; bool fin{false}; };
    std::vector<PendingStreamWrite> pending_wt_stream_writes;
    std::vector<std::pair<std::uint64_t, std::string>> pending_datagram_echos;  // (quarter_sid, payload)
    std::string wt_capsule_buffer;  // incomplete capsule data on CONNECT stream

    ~QuicConn() {
        if (h3_conn) {
            nghttp3_conn_del(h3_conn);
            h3_conn = nullptr;
        }
        if (conn) {
            ngtcp2_conn_del(conn);
            conn = nullptr;
        }
        if (ssl) {
            SSL_set_app_data(ssl, nullptr);
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (ossl_ctx) {
            ngtcp2_crypto_ossl_ctx_del(ossl_ctx);
            ossl_ctx = nullptr;
        }
    }
};

struct Http3ServerState {
    EventLoop* loop{nullptr};
    UdpSocket socket;
    SSL_CTX* ssl_ctx{nullptr};
    std::string cert_file;
    std::string key_file;
    HttpHandler handler;
    EventLoop::Callback callback;
    sockaddr_storage local_addr{};
    socklen_t local_addrlen{0};

    std::unordered_map<ngtcp2_cid, std::shared_ptr<QuicConn>, CidHash, CidEqual> conns_by_scid;

    void on_readable() {
        std::array<std::uint8_t, MAX_PKT_BUF> buf;
        sockaddr_storage peer{};
        socklen_t peer_len = sizeof(peer);
        std::ptrdiff_t n = socket.recv_from(buf.data(), buf.size(),
                                             reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (n <= 0) return;
        const std::size_t pktlen = static_cast<std::size_t>(n);

        ngtcp2_version_cid version_cid{};
        int decode_rv = ngtcp2_pkt_decode_version_cid(
            &version_cid, buf.data(), pktlen, NGTCP2_SV_SCIDLEN);
        if (decode_rv == NGTCP2_ERR_VERSION_NEGOTIATION)
            return;  // Could send VN packet; skip for minimal impl.
        if (decode_rv != 0)
            return;

        QuicConn* conn_ptr = nullptr;
        if (version_cid.version != 0) {
            // Long header: look up by DCID (our SCID) or accept Initial.
            ngtcp2_cid dcid_key;
            ngtcp2_cid_init(&dcid_key, version_cid.dcid, version_cid.dcidlen);
            auto it = conns_by_scid.find(dcid_key);
            if (it != conns_by_scid.end())
                conn_ptr = it->second.get();
        }
        if (!conn_ptr && version_cid.version != 0) {
            // Possibly Initial packet.
            ngtcp2_pkt_hd hd{};
            if (ngtcp2_accept(&hd, buf.data(), pktlen) != 0)
                return;
            conn_ptr = create_conn(&peer, peer_len, &hd);
            if (!conn_ptr) return;
        }
        if (!conn_ptr && version_cid.version == 0) {
            // Short header: DCID is our SCID.
            ngtcp2_cid dcid_key;
            ngtcp2_cid_init(&dcid_key, version_cid.dcid, version_cid.dcidlen);
            auto it = conns_by_scid.find(dcid_key);
            if (it != conns_by_scid.end())
                conn_ptr = it->second.get();
        }
        if (!conn_ptr) return;

        ngtcp2_path path;
        path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&conn_ptr->path_storage.local_addrbuf);
        path.local.addrlen = conn_ptr->path_storage.path.local.addrlen;
        path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&conn_ptr->path_storage.remote_addrbuf);
        path.remote.addrlen = conn_ptr->path_storage.path.remote.addrlen;

        ngtcp2_tstamp ts = static_cast<ngtcp2_tstamp>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        int rv = ngtcp2_conn_read_pkt(conn_ptr->conn, &path, nullptr,
                                      buf.data(), pktlen, ts);
        if (rv == NGTCP2_ERR_RETRY || rv == NGTCP2_ERR_DROP_CONN) {
            remove_conn(conn_ptr);
            return;
        }
        if (rv != 0 && rv != NGTCP2_ERR_DRAINING && rv != NGTCP2_ERR_CLOSING)
            flush_send(conn_ptr);

        flush_send(conn_ptr);
        std::shared_ptr<QuicConn> sh;
        for (auto& [k, v] : conns_by_scid) {
            if (v.get() == conn_ptr) { sh = v; break; }
        }
        if (sh) schedule_conn_timer(this, sh);
    }

    QuicConn* create_conn(const sockaddr_storage* remote, socklen_t remote_len,
                          const ngtcp2_pkt_hd* hd) {
        ngtcp2_cid dcid, scid;
        dcid.datalen = hd->dcid.datalen;
        std::memcpy(dcid.data, hd->dcid.data, dcid.datalen);
        scid.datalen = NGTCP2_SV_SCIDLEN;
        if (RAND_bytes(scid.data, static_cast<int>(scid.datalen)) != 1)
            return nullptr;

        ngtcp2_path_storage ps;
        ngtcp2_path_storage_init(&ps,
                                reinterpret_cast<const ngtcp2_sockaddr*>(&local_addr), local_addrlen,
                                reinterpret_cast<const ngtcp2_sockaddr*>(remote), remote_len,
                                nullptr);

        auto conn = std::make_shared<QuicConn>();
        conn->server = this;
        conn->path_storage = ps;
        conn->conn_ref.get_conn = [](ngtcp2_crypto_conn_ref* ref) -> ngtcp2_conn* {
            auto* c = static_cast<QuicConn*>(ref->user_data);
            return c ? c->conn : nullptr;
        };
        conn->conn_ref.user_data = conn.get();

        conn->ssl = SSL_new(ssl_ctx);
        if (!conn->ssl) return nullptr;
        SSL_set_app_data(conn->ssl, &conn->conn_ref);
        if (ngtcp2_crypto_ossl_configure_server_session(conn->ssl) != 0) {
            SSL_free(conn->ssl);
            return nullptr;
        }
        if (ngtcp2_crypto_ossl_ctx_new(&conn->ossl_ctx, conn->ssl) != 0) {
            SSL_free(conn->ssl);
            return nullptr;
        }

        ngtcp2_callbacks cb{};
        cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
        cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        cb.encrypt = ngtcp2_crypto_encrypt_cb;
        cb.decrypt = ngtcp2_crypto_decrypt_cb;
        cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
        cb.recv_stream_data = [](ngtcp2_conn* nconn, uint32_t flags, int64_t stream_id,
                                 uint64_t offset, const uint8_t* data, size_t datalen,
                                 void* user_data, void* /*stream_user_data*/) {
            auto* q = static_cast<QuicConn*>(user_data);
            const int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
            if (!q->h3_conn) {
                if (ngtcp2_conn_extend_max_stream_offset(nconn, stream_id, datalen) != 0)
                    return NGTCP2_ERR_CALLBACK_FAILURE;
                return 0;
            }
            // Client-initiated bidirectional (HTTP/3 request or WebTransport bidi).
            if ((stream_id & 3u) == 0) {
                if (q->wt_bidi_streams.count(stream_id) != 0) {
                    int64_t srv_id = q->wt_client_to_server_bidi[stream_id];
                    on_wt_stream_echo_bidi(q, stream_id, data, datalen, fin);
                    if (ngtcp2_conn_extend_max_stream_offset(nconn, stream_id, datalen) != 0)
                        return NGTCP2_ERR_CALLBACK_FAILURE;
                    return 0;
                }
                std::string& buf = q->stream_read_buffer[stream_id];
                buf.append(reinterpret_cast<const char*>(data), datalen);
                if (buf.size() >= 1u && static_cast<std::uint8_t>(buf[0]) != WT_STREAM_SIGNAL_BIDI) {
                    nghttp3_tstamp ts = static_cast<nghttp3_tstamp>(
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now().time_since_epoch()).count());
                    nghttp3_ssize n = nghttp3_conn_read_stream2(q->h3_conn, stream_id,
                        reinterpret_cast<const uint8_t*>(buf.data()), buf.size(), fin, ts);
                    if (n < 0) return NGTCP2_ERR_CALLBACK_FAILURE;
                    q->stream_read_buffer.erase(stream_id);
                    if (ngtcp2_conn_extend_max_stream_offset(nconn, stream_id, datalen) != 0)
                        return NGTCP2_ERR_CALLBACK_FAILURE;
                    return 0;
                }
                if (buf.size() >= 1u) {
                    auto [sid, consumed] = decode_varint(
                        reinterpret_cast<const uint8_t*>(buf.data()) + 1,
                        reinterpret_cast<const uint8_t*>(buf.data()) + buf.size());
                    if (consumed == 0 && buf.size() < 9u) {
                        if (ngtcp2_conn_extend_max_stream_offset(nconn, stream_id, datalen) != 0)
                            return NGTCP2_ERR_CALLBACK_FAILURE;
                        return 0;
                    }
                    size_t header_len = 1 + consumed;
                    if (buf.size() < header_len) {
                        if (ngtcp2_conn_extend_max_stream_offset(nconn, stream_id, datalen) != 0)
                            return NGTCP2_ERR_CALLBACK_FAILURE;
                        return 0;
                    }
                    q->wt_bidi_streams.insert(stream_id);
                    int64_t srv_id = q->next_server_bidi_stream_id;
                    q->next_server_bidi_stream_id += 4;
                    q->wt_client_to_server_bidi[stream_id] = srv_id;
                    std::string echo_data(buf.substr(0, header_len));
                    echo_data.append(buf.substr(header_len));
                    q->pending_wt_stream_writes.push_back(
                        {srv_id, std::move(echo_data), fin != 0});
                    q->stream_read_buffer.erase(stream_id);
                }
                if (ngtcp2_conn_extend_max_stream_offset(nconn, stream_id, datalen) != 0)
                    return NGTCP2_ERR_CALLBACK_FAILURE;
                return 0;
            }
            // Client-initiated unidirectional (WebTransport uni type 0x54).
            if ((stream_id & 3u) == 2) {
                if (q->wt_uni_streams.count(stream_id) != 0) {
                    uint64_t sid = q->wt_uni_session[stream_id];
                    on_wt_stream_echo_uni(q, stream_id, sid, data, datalen, fin);
                    if (ngtcp2_conn_extend_max_stream_offset(nconn, stream_id, datalen) != 0)
                        return NGTCP2_ERR_CALLBACK_FAILURE;
                    return 0;
                }
                if (datalen == 0) {
                    if (ngtcp2_conn_extend_max_stream_offset(nconn, stream_id, 0) != 0)
                        return NGTCP2_ERR_CALLBACK_FAILURE;
                    return 0;
                }
                if (data[0] != WT_STREAM_TYPE_UNI) {
                    if (ngtcp2_conn_extend_max_stream_offset(nconn, stream_id, datalen) != 0)
                        return NGTCP2_ERR_CALLBACK_FAILURE;
                    return 0;
                }
                auto [sid, consumed] = decode_varint(data + 1, data + datalen);
                if (consumed == 0) {
                    if (ngtcp2_conn_extend_max_stream_offset(nconn, stream_id, datalen) != 0)
                        return NGTCP2_ERR_CALLBACK_FAILURE;
                    return 0;
                }
                size_t header_len = 1 + consumed;
                q->wt_uni_streams.insert(stream_id);
                q->wt_uni_session[stream_id] = sid;
                on_wt_stream_echo_uni(q, stream_id, sid, data + header_len, datalen - header_len, fin);
                if (ngtcp2_conn_extend_max_stream_offset(nconn, stream_id, datalen) != 0)
                    return NGTCP2_ERR_CALLBACK_FAILURE;
                return 0;
            }
            nghttp3_tstamp ts = static_cast<nghttp3_tstamp>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
            nghttp3_ssize n = nghttp3_conn_read_stream2(q->h3_conn, stream_id, data, datalen, fin, ts);
            if (n < 0) return NGTCP2_ERR_CALLBACK_FAILURE;
            if (ngtcp2_conn_extend_max_stream_offset(nconn, stream_id, static_cast<uint64_t>(n)) != 0)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            return 0;
        };
        cb.recv_datagram = [](ngtcp2_conn* nconn, uint32_t /*flags*/,
                              const uint8_t* data, size_t datalen, void* user_data) {
            auto* q = static_cast<QuicConn*>(user_data);
            if (datalen == 0) return 0;
            auto [quarter, consumed] = decode_varint(data, data + datalen);
            if (consumed == 0) return 0;
            if (consumed > datalen) return 0;
            uint64_t session_id = quarter_stream_id_to_session_id(quarter);
            if (q->wt_session_stream_id >= 0 && static_cast<uint64_t>(q->wt_session_stream_id) == session_id)
                on_wt_datagram_echo(q->server, q, quarter, data + consumed, datalen - consumed);
            if (ngtcp2_conn_extend_max_stream_offset(nconn, 0, 0) != 0) {}
            return 0;
        };
        cb.acked_stream_data_offset = [](ngtcp2_conn* /*nconn*/, int64_t stream_id,
                                         uint64_t offset, uint64_t datalen,
                                         void* user_data, void* /*stream_user_data*/) {
            auto* q = static_cast<QuicConn*>(user_data);
            if (q->h3_conn)
                nghttp3_conn_add_ack_offset(q->h3_conn, stream_id, datalen);
            return 0;
        };
        cb.stream_open = nullptr;
        cb.stream_close = nullptr;
        cb.handshake_completed = [](ngtcp2_conn* /*nconn*/, void* user_data) {
            auto* q = static_cast<QuicConn*>(user_data);
            nghttp3_callbacks h3cb{};
            h3cb.acked_stream_data = h3_acked_stream_data;
            h3cb.stream_close = h3_stream_close;
            h3cb.recv_data = h3_recv_data;
            h3cb.deferred_consume = h3_deferred_consume;
            h3cb.begin_headers = h3_begin_headers;
            h3cb.recv_header = h3_recv_header;
            h3cb.end_headers = h3_end_headers;
            h3cb.end_stream = h3_end_stream;
            h3cb.stop_sending = h3_stop_sending;
            h3cb.reset_stream = h3_reset_stream;
            nghttp3_settings settings;
            nghttp3_settings_default(&settings);
            settings.enable_connect_protocol = 1;  // Extended CONNECT (RFC 9220) for WebTransport
            settings.h3_datagram = 1;              // HTTP/3 datagrams (RFC 9297)
            if (nghttp3_conn_server_new(&q->h3_conn, &h3cb, &settings, nullptr, q) != 0)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            return 0;
        };
        cb.rand = [](uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx*) {
            (void)RAND_bytes(dest, static_cast<int>(destlen));
        };
        cb.get_new_connection_id = [](ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token,
                                      size_t cidlen, void* user_data) {
            auto* q = static_cast<QuicConn*>(user_data);
            if (RAND_bytes(cid->data, static_cast<int>(cidlen)) != 1)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            cid->datalen = cidlen;
            if (ngtcp2_crypto_generate_stateless_reset_token(
                    token, nullptr, 0, cid) != 0)
                return NGTCP2_ERR_CALLBACK_FAILURE;
            q->server->associate_cid(*cid, q);
            return 0;
        };
        cb.remove_connection_id = [](ngtcp2_conn*, const ngtcp2_cid* cid, void* user_data) {
            auto* q = static_cast<QuicConn*>(user_data);
            q->server->dissociate_cid(cid);
            return 0;
        };
        cb.update_key = ngtcp2_crypto_update_key_cb;
        cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        cb.get_path_challenge_data = [](ngtcp2_conn*, uint8_t* data, void*) {
            return RAND_bytes(data, NGTCP2_PATH_CHALLENGE_DATALEN) == 1 ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
        };
        cb.version_negotiation = [](ngtcp2_conn*, uint32_t, const ngtcp2_cid*, void*) { return 0; };

        ngtcp2_settings settings;
        ngtcp2_settings_default(&settings);
        settings.log_printf = nullptr;
        settings.max_tx_udp_payload_size = MAX_UDP_PAYLOAD;

        ngtcp2_transport_params params;
        ngtcp2_transport_params_default(&params);
        params.initial_max_stream_data_bidi_local = 256 * 1024;
        params.initial_max_stream_data_bidi_remote = 256 * 1024;
        params.initial_max_stream_data_uni = 256 * 1024;
        params.initial_max_data = 512 * 1024;
        params.initial_max_streams_bidi = 100;
        params.initial_max_streams_uni = 100;
        params.max_idle_timeout = 30 * NGTCP2_SECONDS;
        params.max_datagram_frame_size = 2048;  // WebTransport / HTTP/3 datagrams (RFC 9221)

        ngtcp2_conn* nconn = nullptr;
        int rv = ngtcp2_conn_server_new(
            &nconn, &dcid, &scid, &conn->path_storage.path,
            hd->version, &cb, &settings, &params, nullptr, conn.get());
        if (rv != 0) return nullptr;
        conn->conn = nconn;
        ngtcp2_conn_set_tls_native_handle(conn->conn, conn->ossl_ctx);

        ngtcp2_cid scid_key;
        scid_key.datalen = scid.datalen;
        std::memcpy(scid_key.data, scid.data, scid.datalen);
        conns_by_scid[scid_key] = conn;
        return conn.get();
    }

    void associate_cid(const ngtcp2_cid& cid, QuicConn* q) {
        ngtcp2_cid key;
        key.datalen = cid.datalen;
        std::memcpy(key.data, cid.data, cid.datalen);
        if (conns_by_scid.count(key)) return;
        for (auto& [k, v] : conns_by_scid) {
            if (v.get() == q) {
                conns_by_scid[key] = v;
                return;
            }
        }
    }
    void dissociate_cid(const ngtcp2_cid* cid) {
        conns_by_scid.erase(*cid);
    }

    void remove_conn(QuicConn* q) {
        for (auto it = conns_by_scid.begin(); it != conns_by_scid.end(); ) {
            if (it->second.get() == q)
                it = conns_by_scid.erase(it);
            else
                ++it;
        }
    }

    void flush_send(QuicConn* q) {
        std::array<std::uint8_t, MAX_UDP_PAYLOAD> buf;
        ngtcp2_tstamp ts = static_cast<ngtcp2_tstamp>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());

        if (q->h3_conn && !q->h3_ready && q->pending_stream_idx < 3) {
            while (q->pending_stream_idx < 3) {
                ngtcp2_vec v;
                v.base = &q->pending_stream_types[q->pending_stream_idx];
                v.len = 1;
                ngtcp2_ssize pdatalen = 0;
                ngtcp2_ssize n = ngtcp2_conn_writev_stream(
                    q->conn, &q->path_storage.path, nullptr, buf.data(), buf.size(),
                    &pdatalen, NGTCP2_WRITE_STREAM_FLAG_NONE, q->pending_stream_ids[q->pending_stream_idx],
                    &v, 1, ts);
                if (n <= 0) break;
                socket.send_to(buf.data(), static_cast<std::size_t>(n),
                              reinterpret_cast<const sockaddr*>(&q->path_storage.remote_addrbuf),
                              q->path_storage.path.remote.addrlen);
                q->pending_stream_idx++;
            }
            if (q->pending_stream_idx >= 3) {
                if (nghttp3_conn_bind_control_stream(q->h3_conn, 3) == 0 &&
                    nghttp3_conn_bind_qpack_streams(q->h3_conn, 7, 11) == 0)
                    q->h3_ready = true;
            }
        }

        if (q->h3_ready && q->h3_conn) {
            std::array<nghttp3_vec, 16> vecs;
            for (;;) {
                int64_t stream_id = -1;
                int fin = 0;
                nghttp3_ssize nw = nghttp3_conn_writev_stream(q->h3_conn, &stream_id, &fin,
                                                              vecs.data(), vecs.size());
                if (nw < 0) break;
                if (nw == 0 && stream_id == -1) break;
                size_t total = 0;
                for (nghttp3_ssize i = 0; i < nw; ++i) total += vecs[i].len;
                if (total == 0 && !fin) break;
                ngtcp2_vec datav[16];
                for (nghttp3_ssize i = 0; i < nw; ++i) {
                    datav[i].base = vecs[i].base;
                    datav[i].len = vecs[i].len;
                }
                ngtcp2_ssize pdatalen = -1;
                uint32_t wflags = fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : NGTCP2_WRITE_STREAM_FLAG_NONE;
                ngtcp2_ssize n = ngtcp2_conn_writev_stream(
                    q->conn, &q->path_storage.path, nullptr, buf.data(), buf.size(),
                    &pdatalen, wflags, stream_id,
                    datav, static_cast<size_t>(nw), ts);
                if (n <= 0) break;
                socket.send_to(buf.data(), static_cast<std::size_t>(n),
                              reinterpret_cast<const sockaddr*>(&q->path_storage.remote_addrbuf),
                              q->path_storage.path.remote.addrlen);
                nghttp3_conn_add_write_offset(q->h3_conn, stream_id, total);
            }
        }

        // WebTransport: flush pending stream writes (bidi/uni echo).
        while (!q->pending_wt_stream_writes.empty()) {
            auto& w = q->pending_wt_stream_writes.front();
            ngtcp2_vec v;
            v.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(w.data.data()));
            v.len = w.data.size();
            ngtcp2_ssize pdatalen = -1;
            uint32_t wflags = w.fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : NGTCP2_WRITE_STREAM_FLAG_NONE;
            ngtcp2_ssize n = ngtcp2_conn_writev_stream(
                q->conn, &q->path_storage.path, nullptr, buf.data(), buf.size(),
                &pdatalen, wflags, w.stream_id, &v, 1, ts);
            if (n <= 0) break;
            socket.send_to(buf.data(), static_cast<std::size_t>(n),
                          reinterpret_cast<const sockaddr*>(&q->path_storage.remote_addrbuf),
                          q->path_storage.path.remote.addrlen);
            q->pending_wt_stream_writes.erase(q->pending_wt_stream_writes.begin());
        }

        // WebTransport: flush pending QUIC datagram echos (HTTP/3 datagram format).
        while (!q->pending_datagram_echos.empty()) {
            auto& [quarter, payload] = q->pending_datagram_echos.front();
            std::array<std::uint8_t, 8> qbuf{};
            std::size_t qlen = encode_varint(qbuf.data(), quarter);
            ngtcp2_vec datav[2];
            datav[0].base = qbuf.data();
            datav[0].len = qlen;
            datav[1].base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(payload.data()));
            datav[1].len = payload.size();
            int accepted = 0;
            ngtcp2_ssize n = ngtcp2_conn_writev_datagram(q->conn, &q->path_storage.path, nullptr,
                buf.data(), buf.size(), &accepted, NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0, datav, 2, ts);
            if (n <= 0) break;
            socket.send_to(buf.data(), static_cast<std::size_t>(n),
                          reinterpret_cast<const sockaddr*>(&q->path_storage.remote_addrbuf),
                          q->path_storage.path.remote.addrlen);
            q->pending_datagram_echos.erase(q->pending_datagram_echos.begin());
        }

        // WebTransport: flush pending capsule echos on CONNECT stream (DATAGRAM capsule).
        while (q->wt_session_stream_id >= 0 && !q->pending_capsule_echos.empty()) {
            const std::string& pl = q->pending_capsule_echos.front().payload;
            std::array<std::uint8_t, 16> cap{};
            std::size_t off = 0;
            off += encode_varint(cap.data() + off, CAPSULE_TYPE_DATAGRAM);
            off += encode_varint(cap.data() + off, pl.size());
            ngtcp2_vec v[2];
            v[0].base = cap.data();
            v[0].len = off;
            v[1].base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(pl.data()));
            v[1].len = pl.size();
            ngtcp2_ssize pdatalen = -1;
            ngtcp2_ssize n = ngtcp2_conn_writev_stream(
                q->conn, &q->path_storage.path, nullptr, buf.data(), buf.size(),
                &pdatalen, NGTCP2_WRITE_STREAM_FLAG_NONE, q->wt_session_stream_id, v, 2, ts);
            if (n <= 0) break;
            socket.send_to(buf.data(), static_cast<std::size_t>(n),
                          reinterpret_cast<const sockaddr*>(&q->path_storage.remote_addrbuf),
                          q->path_storage.path.remote.addrlen);
            q->pending_capsule_echos.erase(q->pending_capsule_echos.begin());
        }

        for (;;) {
            ngtcp2_ssize n = ngtcp2_conn_write_pkt(
                q->conn, &q->path_storage.path, nullptr,
                buf.data(), buf.size(), ts);
            if (n <= 0) break;
            socket.send_to(buf.data(), static_cast<std::size_t>(n),
                          reinterpret_cast<const sockaddr*>(&q->path_storage.remote_addrbuf),
                          q->path_storage.path.remote.addrlen);
        }
    }
};

static void on_wt_datagram_echo(Http3ServerState* /*state*/, QuicConn* q,
    std::uint64_t quarter_stream_id, const std::uint8_t* payload, std::size_t payloadlen) {
    q->pending_datagram_echos.emplace_back(quarter_stream_id,
        std::string(reinterpret_cast<const char*>(payload), payloadlen));
}

static void on_wt_stream_echo_bidi(QuicConn* q, int64_t client_stream_id,
    const std::uint8_t* data, std::size_t datalen, int fin) {
    auto it = q->wt_client_to_server_bidi.find(client_stream_id);
    if (it == q->wt_client_to_server_bidi.end()) return;
    q->pending_wt_stream_writes.push_back({
        it->second,
        std::string(reinterpret_cast<const char*>(data), datalen),
        fin != 0
    });
}

static void on_wt_stream_echo_uni(QuicConn* q, int64_t client_stream_id,
    std::uint64_t session_id, const std::uint8_t* data, std::size_t datalen, int fin) {
    int64_t srv_id;
    auto it = q->wt_uni_client_to_server.find(client_stream_id);
    if (it == q->wt_uni_client_to_server.end()) {
        srv_id = q->next_server_uni_stream_id;
        q->next_server_uni_stream_id += 4;
        q->wt_uni_client_to_server[client_stream_id] = srv_id;
        std::string header;
        header.push_back(static_cast<char>(WT_STREAM_TYPE_UNI));
        std::array<std::uint8_t, 8> vbuf{};
        std::size_t vlen = encode_varint(vbuf.data(), session_id);
        header.append(reinterpret_cast<char*>(vbuf.data()), vlen);
        header.append(reinterpret_cast<const char*>(data), datalen);
        q->pending_wt_stream_writes.push_back({srv_id, std::move(header), fin != 0});
    } else {
        srv_id = it->second;
        q->pending_wt_stream_writes.push_back({
            srv_id,
            std::string(reinterpret_cast<const char*>(data), datalen),
            fin != 0
        });
    }
}

// ----- nghttp3 callbacks (conn_user_data = QuicConn*) -----
static int h3_begin_headers(nghttp3_conn* /*conn*/, int64_t stream_id,
                             void* conn_user_data, void* /*stream_user_data*/) {
    auto* q = static_cast<QuicConn*>(conn_user_data);
    q->stream_requests[stream_id] = H3StreamReq{};
    return 0;
}

static int h3_recv_header(nghttp3_conn* /*conn*/, int64_t stream_id, int32_t token,
                          nghttp3_rcbuf* name, nghttp3_rcbuf* value, uint8_t /*flags*/,
                          void* conn_user_data, void* /*stream_user_data*/) {
    auto* q = static_cast<QuicConn*>(conn_user_data);
    auto it = q->stream_requests.find(stream_id);
    if (it == q->stream_requests.end()) return 0;
    nghttp3_vec nv = nghttp3_rcbuf_get_buf(name);
    nghttp3_vec vv = nghttp3_rcbuf_get_buf(value);
    std::string_view n(reinterpret_cast<const char*>(nv.base), nv.len);
    std::string_view v(reinterpret_cast<const char*>(vv.base), vv.len);
    auto& req = it->second.request;
    if (token == NGHTTP3_QPACK_TOKEN__METHOD) {
        if (v == "GET") req.method = HttpMethod::Get;
        else if (v == "POST") req.method = HttpMethod::Post;
        else if (v == "HEAD") req.method = HttpMethod::Head;
        else if (v == "PUT") req.method = HttpMethod::Put;
        else if (v == "DELETE") req.method = HttpMethod::Delete;
        else if (v == "OPTIONS") req.method = HttpMethod::Options;
        else req.method = HttpMethod::Unknown;
    } else if (token == NGHTTP3_QPACK_TOKEN__PATH) {
        std::string pathv(v);
        std::size_t qpos = pathv.find('?');
        if (qpos != std::string::npos) {
            req.path = pathv.substr(0, qpos);
            req.query = pathv.substr(qpos + 1);
        } else {
            req.path = std::move(pathv);
        }
    } else if (token == NGHTTP3_QPACK_TOKEN__PROTOCOL) {
        if (v == "webtransport")
            it->second.is_webtransport_connect = true;
    } else if (token != NGHTTP3_QPACK_TOKEN__SCHEME && token != NGHTTP3_QPACK_TOKEN__AUTHORITY) {
        req.headers.emplace_back(std::string(n), std::string(v));
    }
    return 0;
}

static int h3_end_headers(nghttp3_conn* /*conn*/, int64_t /*stream_id*/, int /*fin*/,
                         void* /*conn_user_data*/, void* /*stream_user_data*/) {
    return 0;
}

static nghttp3_ssize h3_read_data(nghttp3_conn* /*c*/, int64_t sid, nghttp3_vec* vec, size_t veccnt,
                                  uint32_t* pflags, void* user_data, void* /*stream_user_data*/) {
    auto* quic = static_cast<QuicConn*>(user_data);
    auto it = quic->stream_response_bodies.find(sid);
    if (it == quic->stream_response_bodies.end() || it->second.empty()) {
        *pflags = NGHTTP3_DATA_FLAG_EOF;
        return 0;
    }
    std::string& s = it->second;
    if (veccnt == 0) return 0;
    vec[0].base = reinterpret_cast<uint8_t*>(s.data());
    vec[0].len = s.size();
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    return 1;
}

static int h3_end_stream(nghttp3_conn* conn, int64_t stream_id,
                         void* conn_user_data, void* /*stream_user_data*/) {
    auto* q = static_cast<QuicConn*>(conn_user_data);
    auto it = q->stream_requests.find(stream_id);
    if (it == q->stream_requests.end()) return 0;
    if (it->second.is_webtransport_connect) {
        q->wt_session_stream_id = stream_id;
        static const uint8_t status_name[] = ":status";
        static const uint8_t status_val[] = "200";
        static const uint8_t capsule_name[] = "capsule-protocol";
        static const uint8_t capsule_val[] = "?1";
        const nghttp3_nv nva[] = {
            {const_cast<uint8_t*>(status_name), const_cast<uint8_t*>(status_val), 7, 3, NGHTTP3_NV_FLAG_NONE},
            {const_cast<uint8_t*>(capsule_name), const_cast<uint8_t*>(capsule_val), 15, 2, NGHTTP3_NV_FLAG_NONE},
        };
        int rv = nghttp3_conn_submit_response(conn, stream_id, nva, 2, nullptr);
        if (rv != 0) return NGHTTP3_ERR_CALLBACK_FAILURE;
        q->stream_requests.erase(it);
        flush_send_quic(q->server, q);
        return 0;
    }
    if (!q->server->handler) return 0;
    const HttpRequest& req = it->second.request;
    std::string body = q->server->handler(req);
    if (body.size() >= 9 && body.substr(0, 9) == "HTTP/1.1 ")
        body.clear();
    if (body.empty())
        body = make_http_ok("");
    else if (body.size() < 9 || body.substr(0, 9) != "HTTP/1.1 ")
        body = make_http_ok(body, "text/html; charset=utf-8");
    std::string_view rest(body);
    auto crlf = rest.find("\r\n");
    if (crlf == std::string_view::npos) crlf = rest.size();
    rest = crlf + 2 <= rest.size() ? rest.substr(crlf + 2) : std::string_view{};
    int status = 200;
    std::string resp_body;
    while (!rest.empty()) {
        auto line_end = rest.find("\r\n");
        if (line_end == std::string_view::npos) line_end = rest.size();
        std::string_view line = rest.substr(0, line_end);
        rest = line_end + 2 <= rest.size() ? rest.substr(line_end + 2) : std::string_view{};
        if (line.empty()) { resp_body = std::string(rest); break; }
        if (line.size() >= 9 && line.substr(0, 8) == "HTTP/1.1 ") {
            char* end = nullptr;
            status = static_cast<int>(std::strtol(line.data() + 9, &end, 10));
            continue;
        }
        auto colon = line.find(':');
        if (colon != std::string_view::npos) continue;
    }
    if (resp_body.empty()) {
        auto body_start = body.find("\r\n\r\n");
        if (body_start != std::string::npos)
            resp_body = body.substr(body_start + 4);
    }
    q->stream_response_bodies[stream_id] = std::move(resp_body);
    const uint8_t status_name[] = ":status";
    std::string status_str = std::to_string(status);
    const uint8_t ct_name[] = "content-type";
    const uint8_t ct_value[] = "text/html; charset=utf-8";
    nghttp3_nv nva[] = {
        {const_cast<uint8_t*>(status_name), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(status_str.c_str())), 7, status_str.size(), NGHTTP3_NV_FLAG_NONE},
        {const_cast<uint8_t*>(ct_name), const_cast<uint8_t*>(ct_value), 12, 23, NGHTTP3_NV_FLAG_NONE},
    };
    nghttp3_data_reader dr{};
    dr.read_data = h3_read_data;
    int rv = nghttp3_conn_submit_response(conn, stream_id, nva, 2, &dr);
    if (rv != 0) return NGHTTP3_ERR_CALLBACK_FAILURE;
    q->stream_requests.erase(it);
    flush_send_quic(q->server, q);
    return 0;
}

static int h3_recv_data(nghttp3_conn* /*conn*/, int64_t stream_id,
                        const uint8_t* data, size_t datalen,
                        void* conn_user_data, void* /*stream_user_data*/) {
    auto* q = static_cast<QuicConn*>(conn_user_data);
    if (stream_id == q->wt_session_stream_id) {
        q->wt_capsule_buffer.append(reinterpret_cast<const char*>(data), datalen);
        size_t consumed = 0;
        const uint8_t* base = reinterpret_cast<const uint8_t*>(q->wt_capsule_buffer.data());
        const uint8_t* end = base + q->wt_capsule_buffer.size();
        const uint8_t* p = base;
        while (p < end) {
            if (p + 1 > end) break;
            auto [ctype, tlen] = decode_varint(p, end);
            if (tlen == 0) break;
            p += tlen;
            if (p >= end) break;
            auto [clen, llen] = decode_varint(p, end);
            if (llen == 0) break;
            p += llen;
            if (static_cast<size_t>(end - p) < clen) break;
            if (ctype == CAPSULE_TYPE_DATAGRAM)
                q->pending_capsule_echos.push_back({std::string(reinterpret_cast<const char*>(p), clen)});
            p += clen;
            consumed = static_cast<size_t>(p - base);
        }
        if (consumed != 0)
            q->wt_capsule_buffer.erase(0, consumed);
        return 0;
    }
    auto it = q->stream_requests.find(stream_id);
    if (it != q->stream_requests.end())
        it->second.request.body.append(reinterpret_cast<const char*>(data), datalen);
    return 0;
}

static int h3_deferred_consume(nghttp3_conn* /*conn*/, int64_t /*stream_id*/, size_t /*consumed*/,
                              void* /*conn_user_data*/, void* /*stream_user_data*/) {
    return 0;
}

static int h3_stream_close(nghttp3_conn* /*conn*/, int64_t stream_id, uint64_t /*app_error_code*/,
                           void* conn_user_data, void* /*stream_user_data*/) {
    auto* q = static_cast<QuicConn*>(conn_user_data);
    if (stream_id == q->wt_session_stream_id)
        q->wt_session_stream_id = -1;
    q->wt_bidi_streams.erase(stream_id);
    q->wt_uni_streams.erase(stream_id);
    q->wt_client_to_server_bidi.erase(stream_id);
    q->wt_uni_session.erase(stream_id);
    q->wt_uni_client_to_server.erase(stream_id);
    q->stream_read_buffer.erase(stream_id);
    q->stream_requests.erase(stream_id);
    q->stream_response_bodies.erase(stream_id);
    return 0;
}

static int h3_stop_sending(nghttp3_conn* /*conn*/, int64_t stream_id, uint64_t /*app_error_code*/,
                           void* conn_user_data, void* /*stream_user_data*/) {
    auto* q = static_cast<QuicConn*>(conn_user_data);
    if (q->conn)
        ngtcp2_conn_shutdown_stream_read(q->conn, 0, stream_id, 0);
    return 0;
}

static int h3_reset_stream(nghttp3_conn* /*conn*/, int64_t stream_id, uint64_t /*app_error_code*/,
                           void* conn_user_data, void* /*stream_user_data*/) {
    auto* q = static_cast<QuicConn*>(conn_user_data);
    if (stream_id == q->wt_session_stream_id)
        q->wt_session_stream_id = -1;
    q->wt_bidi_streams.erase(stream_id);
    q->wt_uni_streams.erase(stream_id);
    q->wt_client_to_server_bidi.erase(stream_id);
    q->wt_uni_session.erase(stream_id);
    q->wt_uni_client_to_server.erase(stream_id);
    q->stream_read_buffer.erase(stream_id);
    q->stream_requests.erase(stream_id);
    q->stream_response_bodies.erase(stream_id);
    if (q->conn)
        ngtcp2_conn_shutdown_stream(q->conn, 0, stream_id, 0);
    return 0;
}

static int h3_acked_stream_data(nghttp3_conn* /*conn*/, int64_t /*stream_id*/, uint64_t /*datalen*/,
                                void* /*conn_user_data*/, void* /*stream_user_data*/) {
    return 0;
}

static void flush_send_quic(Http3ServerState* state, QuicConn* q) {
    if (state && q) state->flush_send(q);
}

static void schedule_conn_timer(Http3ServerState* state, std::shared_ptr<QuicConn> conn) {
    if (!state || !conn || !conn->conn || conn->timer_scheduled) return;
    ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn->conn);
    ngtcp2_tstamp now = static_cast<ngtcp2_tstamp>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    if (expiry <= now) {
        ngtcp2_conn_handle_expiry(conn->conn, now);
        state->flush_send(conn.get());
        schedule_conn_timer(state, conn);
        return;
    }
    auto delay_ms = (expiry - now) / 1000000;
    if (delay_ms == 0) delay_ms = 1;
    conn->timer_scheduled = true;
    state->loop->run_after(std::chrono::milliseconds(delay_ms), [state, conn]() {
        conn->timer_scheduled = false;
        if (!conn->conn) return;
        ngtcp2_tstamp ts = static_cast<ngtcp2_tstamp>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        int rv = ngtcp2_conn_handle_expiry(conn->conn, ts);
        if (rv == NGTCP2_ERR_CLOSING || rv == NGTCP2_ERR_DRAINING)
            state->remove_conn(conn.get());
        else
            state->flush_send(conn.get());
        schedule_conn_timer(state, conn);
    });
}

static std::vector<std::shared_ptr<void>> g_http3_servers;

static int alpn_select_cb(SSL* /*ssl*/, const unsigned char** out, unsigned char* outlen,
                          const unsigned char* in, unsigned int inlen, void* /*arg*/) {
    static const unsigned char h3[] = NGHTTP3_ALPN_H3;
    for (unsigned int i = 0; i < inlen; ) {
        unsigned char len = in[i++];
        if (i + len > inlen) break;
        if (len == sizeof(h3) - 1 && std::memcmp(in + i, h3 + 1, len) == 0) {
            *out = h3 + 1;
            *outlen = len;
            return SSL_TLSEXT_ERR_OK;
        }
        i += len;
    }
    return SSL_TLSEXT_ERR_NOACK;
}

static SSL_CTX* create_ssl_ctx(const char* cert_file, const char* key_file) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) return nullptr;
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        return nullptr;
    }
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, nullptr);
    return ctx;
}

}  // namespace

void run_http3_server(EventLoop& loop,
                      const char* host,
                      std::uint16_t port,
                      const char* cert_file,
                      const char* key_file,
                      const HttpHandler& handler) {
    if (ngtcp2_crypto_ossl_init() != 0) {
        std::cerr << "http3_server: ngtcp2_crypto_ossl_init failed\n";
        return;
    }
    auto state = std::make_shared<Http3ServerState>();
    state->loop = &loop;
    state->cert_file = cert_file ? cert_file : "";
    state->key_file = key_file ? key_file : "";
    state->handler = handler;
    state->callback = [state]() { state->on_readable(); };

    state->ssl_ctx = create_ssl_ctx(state->cert_file.c_str(), state->key_file.c_str());
    if (!state->ssl_ctx) {
        std::cerr << "http3_server: SSL_CTX creation failed (check cert/key)\n";
        return;
    }

    try {
        state->socket.bind(host, port);
    } catch (const std::exception& e) {
        std::cerr << "http3_server: bind failed: " << e.what() << std::endl;
        SSL_CTX_free(state->ssl_ctx);
        return;
    }
    state->local_addrlen = sizeof(state->local_addr);
    if (getsockname(state->socket.fd(), reinterpret_cast<sockaddr*>(&state->local_addr),
                    &state->local_addrlen) < 0) {
        std::cerr << "http3_server: getsockname failed\n";
        state->socket.close();
        SSL_CTX_free(state->ssl_ctx);
        return;
    }

    state->socket.set_event_loop(&loop);
    loop.register_fd(state->socket.fd(), PollEvent::Read, &state->callback);
    g_http3_servers.push_back(state);
    std::cout << "HTTP/3 (QUIC) server listening on " << (host ? host : "0.0.0.0") << ":" << port
              << " (ngtcp2 + nghttp3, Hello World)." << std::endl;
}

}  // namespace peimon
