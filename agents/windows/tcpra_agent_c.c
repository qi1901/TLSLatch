#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include "windivert.h"
#include "guardian.h"

#define RA_MAGIC 0x43535631u
#define RA_VERSION 5u
#define RA_REQUEST 1u
#define RA_RESPONSE 2u
#define RA_VERDICT 3u

#define CSV_REPORT_SIZE 2548u
#define USER_DATA_OFFSET 64u
#define MEASUREMENT_OFFSET 144u
#define SIGNED_SIZE 180u
#define ANONCE_OFFSET 188u
#define REPORT_SIGNATURE_OFFSET 192u
#define REPORT_PEK_OFFSET 336u
#define CSV_CERT_SIZE 2084u
#define CERT_POINT_OFFSET 16u
#define POINT_X_OFFSET 4u
#define POINT_Y_OFFSET 76u
#define POINT_UID_OFFSET 148u

#define PACKET_CAP 65535u
#define TLS_CAP (256u * 1024u)
#define HELD_CAP (32u * 1024u * 1024u)
#define QUEUE_CAP 4096u
#define ERROR_CAP 512u

#define TRUSTED_PEK_HEX getenv("CSV_RA_TRUSTED_PEK")
#define TRUSTED_MEASUREMENT_HEX getenv("CSV_RA_TRUSTED_MEASURE")

typedef struct {
    bool ra;
    IN_ADDR server_addr;
    char server_ip[INET_ADDRSTRLEN];
    uint16_t main_port, ra_port;
    size_t expected, workers;
    DWORD timeout_ms;
    const char *output, *self_test_report;
} Config;

typedef struct {
    uint8_t local_ip[4], remote_ip[4];
    uint16_t local_port, remote_port;
} FlowKey;

typedef struct {
    FlowKey flow;
    uint32_t sequence;
    bool outbound, syn, ack, fin, rst;
    const uint8_t *payload;
    size_t payload_len;
} PacketView;

typedef struct HeldPacket {
    struct HeldPacket *next;
    UINT length;
    WINDIVERT_ADDRESS address;
    uint8_t bytes[1];
} HeldPacket;

typedef struct {
    uint8_t *data;
    size_t length, capacity;
} ByteBuffer;

typedef struct {
    size_t session;
    bool ra, success, verified;
    FlowKey flow;
    uint8_t lookup_key[64], local_serverhello_key[64], response_report_key[64];
    bool have_lookup_key, have_local_serverhello_key, have_response_report_key;
    uint64_t opened_ns, client_hello_ns, server_hello_ns, request_start_ns;
    uint64_t response_done_ns, verify_start_ns, verify_done_ns, decision_ns, closed_ns;
    uint64_t packets_copied, bytes_copied, held_packets, released_packets;
    uint32_t response_status;
    bool key_match, report_verify, remote_verdict_sent;
    size_t control_worker;
    bool control_reused;
    char error[ERROR_CAP];
} Row;

typedef struct {
    CRITICAL_SECTION lock;
    CONDITION_VARIABLE not_empty, not_full;
    void **items;
    size_t capacity, head, tail, count;
    bool closed;
} PtrQueue;

struct Context;
typedef struct Session {
    struct Context *context;
    CRITICAL_SECTION lock;
    CONDITION_VARIABLE changed;
    HANDLE control_done;
    size_t id;
    FlowKey flow;
    HANDLE divert;
    char filter[768];
    ByteBuffer client_tls, server_tls;
    HeldPacket *held_head, *held_tail;
    size_t held_bytes;
    Row row;
    bool worker_started, decision_done, allowed, fin_seen;
} Session;

typedef struct Context {
    Config config;
    PtrQueue flow_queue, control_queue;
    HANDLE *flow_threads, *control_threads;
    size_t flow_worker_count;
    Row *rows;
    CRITICAL_SECTION completed_lock, denied_lock;
    size_t completed;
    HANDLE all_complete;
    HANDLE *denied_handles;
    size_t denied_count, denied_capacity;
} Context;

typedef struct {
    Context *context;
    size_t worker_id;
} WorkerArg;

static uint16_t read_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static uint32_t read_be24(const uint8_t *p) {
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}
static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static uint32_t read_le32(const uint8_t *p) {
    return p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint16_t read_le16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}
static void write_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
static void write_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint64_t now_ns(void) {
    FILETIME ft;
    ULARGE_INTEGER v;
    GetSystemTimePreciseAsFileTime(&ft);
    v.LowPart = ft.dwLowDateTime;
    v.HighPart = ft.dwHighDateTime;
    return v.QuadPart < 116444736000000000ULL ? 0 : (v.QuadPart - 116444736000000000ULL) * 100ULL;
}

static void append_error(Row *row, const char *message) {
    size_t used;
    if (!message || !*message)
        return;
    used = strlen(row->error);
    if (used && used + 2 < sizeof(row->error)) {
        row->error[used++] = ';';
        row->error[used++] = ' ';
        row->error[used] = 0;
    }
    if (used + 1 < sizeof(row->error))
        strncat_s(row->error, sizeof(row->error), message, _TRUNCATE);
}
static void append_win_error(Row *row, const char *prefix, DWORD code) {
    char text[160];
    _snprintf_s(text, sizeof(text), _TRUNCATE, "%s (winerr=%lu)", prefix, (unsigned long)code);
    append_error(row, text);
}

static bool hex_decode(const char *text, uint8_t *out, size_t length) {
    size_t i;
    if (!text || strlen(text) != length * 2 || strspn(text, "0123456789abcdefABCDEF") != length * 2)
        return false;
    for (i = 0; i < length; i++) {
        unsigned v;
        if (sscanf_s(text + i * 2, "%2x", &v) != 1)
            return false;
        out[i] = (uint8_t)v;
    }
    return true;
}
static void hex_encode(const uint8_t *in, size_t length, char *out) {
    static const char d[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < length; i++) {
        out[i * 2] = d[in[i] >> 4];
        out[i * 2 + 1] = d[in[i] & 15];
    }
    out[length * 2] = 0;
}

static bool buffer_append(ByteBuffer *b, const uint8_t *data, size_t length) {
    size_t wanted, capacity;
    uint8_t *next;
    if (!length)
        return true;
    if (b->length >= TLS_CAP || length > TLS_CAP - b->length)
        return false;
    wanted = b->length + length;
    if (wanted > b->capacity) {
        capacity = b->capacity ? b->capacity : 4096u;
        while (capacity < wanted && capacity < TLS_CAP / 2)
            capacity *= 2;
        if (capacity < wanted)
            capacity = TLS_CAP;
        next = (uint8_t *)realloc(b->data, capacity);
        if (!next)
            return false;
        b->data = next;
        b->capacity = capacity;
    }
    memcpy(b->data + b->length, data, length);
    b->length = wanted;
    return true;
}
static void buffer_free(ByteBuffer *b) {
    free(b->data);
    memset(b, 0, sizeof(*b));
}

static bool queue_init(PtrQueue *q, size_t capacity) {
    memset(q, 0, sizeof(*q));
    InitializeCriticalSection(&q->lock);
    InitializeConditionVariable(&q->not_empty);
    InitializeConditionVariable(&q->not_full);
    q->items = (void **)calloc(capacity, sizeof(void *));
    if (!q->items) {
        DeleteCriticalSection(&q->lock);
        return false;
    }
    q->capacity = capacity;
    return true;
}
static bool queue_push(PtrQueue *q, void *item) {
    EnterCriticalSection(&q->lock);
    while (!q->closed && q->count == q->capacity)
        SleepConditionVariableCS(&q->not_full, &q->lock, INFINITE);
    if (q->closed) {
        LeaveCriticalSection(&q->lock);
        return false;
    }
    q->items[q->tail] = item;
    q->tail = (q->tail + 1) % q->capacity;
    q->count++;
    WakeConditionVariable(&q->not_empty);
    LeaveCriticalSection(&q->lock);
    return true;
}
static void *queue_pop(PtrQueue *q) {
    void *item;
    EnterCriticalSection(&q->lock);
    while (!q->closed && q->count == 0)
        SleepConditionVariableCS(&q->not_empty, &q->lock, INFINITE);
    if (!q->count) {
        LeaveCriticalSection(&q->lock);
        return NULL;
    }
    item = q->items[q->head];
    q->head = (q->head + 1) % q->capacity;
    q->count--;
    WakeConditionVariable(&q->not_full);
    LeaveCriticalSection(&q->lock);
    return item;
}
static void queue_close(PtrQueue *q) {
    EnterCriticalSection(&q->lock);
    q->closed = true;
    WakeAllConditionVariable(&q->not_empty);
    WakeAllConditionVariable(&q->not_full);
    LeaveCriticalSection(&q->lock);
}
static void queue_destroy(PtrQueue *q) {
    free(q->items);
    DeleteCriticalSection(&q->lock);
}

static HANDLE divert_open(const char *filter, INT16 priority, UINT64 flags, char *error,
                          size_t cap) {
    HANDLE h = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, priority, flags);
    if (h == INVALID_HANDLE_VALUE) {
        _snprintf_s(error, cap, _TRUNCATE, "WinDivertOpen failed (winerr=%lu)",
                    (unsigned long)GetLastError());
        return h;
    }
    (void)WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_LENGTH, 16384u);
    (void)WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_SIZE, 32u * 1024u * 1024u);
    (void)WinDivertSetParam(h, WINDIVERT_PARAM_QUEUE_TIME, 16000u);
    return h;
}
static bool divert_send(HANDLE h, const uint8_t *packet, UINT length,
                        const WINDIVERT_ADDRESS *address) {
    UINT sent = 0;
    return WinDivertSend(h, packet, length, &sent, address) && sent == length;
}

static bool packet_view(const uint8_t *bytes, size_t length, const Config *c, PacketView *v) {
    size_t ihl, thl, payload;
    const uint8_t *src, *dst;
    uint16_t sport, dport;
    uint8_t flags;
    if (length < 40 || bytes[0] >> 4 != 4 || bytes[9] != 6)
        return false;
    ihl = (size_t)(bytes[0] & 15) * 4;
    if (ihl < 20 || length < ihl + 20)
        return false;
    thl = (size_t)(bytes[ihl + 12] >> 4) * 4;
    if (thl < 20 || length < ihl + thl)
        return false;
    src = bytes + 12;
    dst = bytes + 16;
    sport = read_be16(bytes + ihl);
    dport = read_be16(bytes + ihl + 2);
    memset(v, 0, sizeof(*v));
    v->sequence = read_be32(bytes + ihl + 4);
    if (!memcmp(dst, &c->server_addr.S_un.S_addr, 4) && dport == c->main_port) {
        memcpy(v->flow.local_ip, src, 4);
        memcpy(v->flow.remote_ip, dst, 4);
        v->flow.local_port = sport;
        v->flow.remote_port = dport;
        v->outbound = true;
    } else if (!memcmp(src, &c->server_addr.S_un.S_addr, 4) && sport == c->main_port) {
        memcpy(v->flow.local_ip, dst, 4);
        memcpy(v->flow.remote_ip, src, 4);
        v->flow.local_port = dport;
        v->flow.remote_port = sport;
    } else
        return false;
    flags = bytes[ihl + 13];
    v->fin = !!(flags & 1);
    v->syn = !!(flags & 2);
    v->rst = !!(flags & 4);
    v->ack = !!(flags & 16);
    payload = ihl + thl;
    v->payload = bytes + payload;
    v->payload_len = length - payload;
    return true;
}

static void ip_text(const uint8_t ip[4], char out[INET_ADDRSTRLEN]) {
    IN_ADDR a;
    memcpy(&a.S_un.S_addr, ip, 4);
    if (!InetNtopA(AF_INET, &a, out, INET_ADDRSTRLEN))
        strcpy_s(out, INET_ADDRSTRLEN, "0.0.0.0");
}
static void exact_filter(const FlowKey *flow, char *out, size_t cap) {
    char local[INET_ADDRSTRLEN], remote[INET_ADDRSTRLEN];
    ip_text(flow->local_ip, local);
    ip_text(flow->remote_ip, remote);
    _snprintf_s(out, cap, _TRUNCATE,
                "ip and tcp and (((ip.SrcAddr == %s and tcp.SrcPort == %u and "
                "ip.DstAddr == %s and tcp.DstPort == %u) or (ip.SrcAddr == %s and "
                "tcp.SrcPort == %u and ip.DstAddr == %s and tcp.DstPort == %u)))",
                local, flow->local_port, remote, flow->remote_port, remote, flow->remote_port,
                local, flow->local_port);
}

static bool sha512_parts(const char *label, const uint8_t *data, size_t length,
                         uint8_t output[64]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned n = 0;
    bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) == 1 &&
              EVP_DigestUpdate(ctx, label, strlen(label)) == 1 &&
              EVP_DigestUpdate(ctx, data, length) == 1 &&
              EVP_DigestFinal_ex(ctx, output, &n) == 1 && n == 64;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static bool parse_client_key_share(const uint8_t *h, size_t length, const uint8_t **ext,
                                   size_t *ext_len) {
    size_t p = 0, n, end;
    if (length < 35)
        return false;
    p = 34;
    n = h[p++];
    if (p + n + 2 > length)
        return false;
    p += n;
    n = read_be16(h + p);
    p += 2;
    if (p + n + 1 > length)
        return false;
    p += n;
    n = h[p++];
    if (p + n + 2 > length)
        return false;
    p += n;
    n = read_be16(h + p);
    p += 2;
    if (p + n > length)
        return false;
    end = p + n;
    while (p + 4 <= end) {
        uint16_t type = read_be16(h + p);
        size_t item = read_be16(h + p + 2);
        p += 4;
        if (p + item > end)
            return false;
        if (type == 51) {
            *ext = h + p;
            *ext_len = item;
            return true;
        }
        p += item;
    }
    return false;
}
static bool parse_server_key_share(const uint8_t *h, size_t length, const uint8_t **ext,
                                   size_t *ext_len) {
    size_t p = 0, n, end;
    if (length < 35)
        return false;
    p = 34;
    n = h[p++];
    if (p + n + 5 > length)
        return false;
    p += n + 3;
    n = read_be16(h + p);
    p += 2;
    if (p + n > length)
        return false;
    end = p + n;
    while (p + 4 <= end) {
        uint16_t type = read_be16(h + p);
        size_t item = read_be16(h + p + 2);
        p += 4;
        if (p + item > end)
            return false;
        if (type == 51) {
            *ext = h + p;
            *ext_len = item;
            return true;
        }
        p += item;
    }
    return false;
}

static bool find_hello_key(const uint8_t *records, size_t length, bool client, uint8_t key[64]) {
    size_t record = 0, hs_len = 0, hs_cap = 0, p = 0;
    uint8_t *hs = NULL;
    bool found = false;
    while (record + 5 <= length) {
        size_t n = read_be16(records + record + 3);
        if (record + 5 + n > length)
            break;
        if (records[record] == 22 && n) {
            uint8_t *next;
            size_t cap;
            if (hs_len + n > TLS_CAP)
                break;
            if (hs_len + n > hs_cap) {
                cap = hs_cap ? hs_cap : 4096;
                while (cap < hs_len + n && cap < TLS_CAP / 2)
                    cap *= 2;
                if (cap < hs_len + n)
                    cap = TLS_CAP;
                next = (uint8_t *)realloc(hs, cap);
                if (!next)
                    goto done;
                hs = next;
                hs_cap = cap;
            }
            memcpy(hs + hs_len, records + record + 5, n);
            hs_len += n;
        }
        record += 5 + n;
    }
    while (p + 4 <= hs_len) {
        uint8_t type = hs[p];
        size_t body = read_be24(hs + p + 1);
        const uint8_t *ext = NULL;
        size_t ext_len = 0;
        if (p + 4 + body > hs_len)
            break;
        if ((client && type == 1 && parse_client_key_share(hs + p + 4, body, &ext, &ext_len)) ||
            (!client && type == 2 && parse_server_key_share(hs + p + 4, body, &ext, &ext_len))) {
            found = sha512_parts(client ? "tcp-level-ra/clienthello-key/v1"
                                        : "tcp-level-ra/serverhello-key/v1",
                                 ext, ext_len, key);
            break;
        }
        p += 4 + body;
    }
done:
    free(hs);
    return found;
}

static void xor_words(const uint8_t *in, uint8_t *out, size_t length, uint32_t nonce) {
    size_t i;
    for (i = 0; i < length; i += 4) {
        uint32_t v = read_le32(in + i) ^ nonce;
        out[i] = (uint8_t)v;
        out[i + 1] = (uint8_t)(v >> 8);
        out[i + 2] = (uint8_t)(v >> 16);
        out[i + 3] = (uint8_t)(v >> 24);
    }
}
static void reverse32(const uint8_t *in, uint8_t out[32]) {
    size_t i;
    for (i = 0; i < 32; i++)
        out[i] = in[31 - i];
}

static bool sm2_verify_signature(const uint8_t report[CSV_REPORT_SIZE], const uint8_t sec1[65],
                                 const uint8_t *uid, size_t uid_len) {
    EC_KEY *ec = NULL;
    const EC_GROUP *group;
    EC_POINT *point = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    ECDSA_SIG *sig = NULL;
    BIGNUM *r = NULL, *s = NULL;
    uint8_t rb[32], sb[32];
    unsigned char *der = NULL, *cursor;
    int der_len;
    bool ok = false;
    reverse32(report + REPORT_SIGNATURE_OFFSET, rb);
    reverse32(report + REPORT_SIGNATURE_OFFSET + 72, sb);
    ec = EC_KEY_new_by_curve_name(NID_sm2);
    if (!ec)
        goto done;
    group = EC_KEY_get0_group(ec);
    point = EC_POINT_new(group);
    if (!point || EC_POINT_oct2point(group, point, sec1, 65, NULL) != 1 ||
        EC_KEY_set_public_key(ec, point) != 1)
        goto done;
    pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, ec) != 1)
        goto done;
    ec = NULL;
    if (EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2) != 1)
        goto done;
    r = BN_bin2bn(rb, 32, NULL);
    s = BN_bin2bn(sb, 32, NULL);
    sig = ECDSA_SIG_new();
    if (!r || !s || !sig || ECDSA_SIG_set0(sig, r, s) != 1)
        goto done;
    r = NULL;
    s = NULL;
    der_len = i2d_ECDSA_SIG(sig, NULL);
    if (der_len <= 0 || !(der = (unsigned char *)malloc((size_t)der_len)))
        goto done;
    cursor = der;
    if (i2d_ECDSA_SIG(sig, &cursor) != der_len)
        goto done;

    md = EVP_MD_CTX_new();
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!md || !pctx || EVP_PKEY_CTX_set1_id(pctx, uid, (int)uid_len) != 1)
        goto done;
    EVP_MD_CTX_set_pkey_ctx(md, pctx);
    if (EVP_DigestVerifyInit(md, NULL, EVP_sm3(), NULL, pkey) != 1 ||
        EVP_DigestVerifyUpdate(md, report, SIGNED_SIZE) != 1 ||
        EVP_DigestVerifyFinal(md, der, (size_t)der_len) != 1)
        goto done;
    ok = true;
done:
    free(der);
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(sig);
    EVP_MD_CTX_free(md);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    EC_POINT_free(point);
    EC_KEY_free(ec);
    return ok;
}

static bool verify_report(const uint8_t report[CSV_REPORT_SIZE], const uint8_t expected[64],
                          char *reason, size_t cap) {
    uint8_t trusted_pek[64], trusted_measurement[32], user_data[64];
    uint8_t pek[CSV_CERT_SIZE], measurement[32], x[32], y[32], actual[64], sec1[65];
    uint32_t nonce;
    size_t point = CERT_POINT_OFFSET, xo, yo, uo, uid_len;
    if (!hex_decode(TRUSTED_PEK_HEX, trusted_pek, 64) ||
        !hex_decode(TRUSTED_MEASUREMENT_HEX, trusted_measurement, 32)) {
        strcpy_s(reason, cap, "invalid built-in trust anchor");
        return false;
    }
    nonce = read_le32(report + ANONCE_OFFSET);
    xor_words(report + USER_DATA_OFFSET, user_data, 64, nonce);
    if (memcmp(user_data, expected, 64)) {
        strcpy_s(reason, cap, "binding mismatch");
        return false;
    }
    xor_words(report + REPORT_PEK_OFFSET, pek, sizeof(pek), nonce);
    if (read_le32(pek + point) != 3) {
        strcpy_s(reason, cap, "invalid curve");
        return false;
    }
    xo = point + POINT_X_OFFSET;
    yo = point + POINT_Y_OFFSET;
    uo = point + POINT_UID_OFFSET;
    reverse32(pek + xo, x);
    reverse32(pek + yo, y);
    uid_len = read_le16(pek + uo);
    if (uid_len > 254 || uo + 2 + uid_len > sizeof(pek)) {
        strcpy_s(reason, cap, "invalid user id");
        return false;
    }
    memcpy(actual, x, 32);
    memcpy(actual + 32, y, 32);
    sec1[0] = 4;
    memcpy(sec1 + 1, x, 32);
    memcpy(sec1 + 33, y, 32);
    if (!sm2_verify_signature(report, sec1, pek + uo + 2, uid_len)) {
        strcpy_s(reason, cap, "signature mismatch");
        return false;
    }
    if (memcmp(actual, trusted_pek, 64)) {
        strcpy_s(reason, cap, "PEK mismatch");
        return false;
    }
    xor_words(report + MEASUREMENT_OFFSET, measurement, 32, nonce);
    if (memcmp(measurement, trusted_measurement, 32)) {
        strcpy_s(reason, cap, "measurement mismatch");
        return false;
    }
    reason[0] = 0;
    return true;
}

static bool send_all(SOCKET s, const uint8_t *data, size_t length) {
    while (length) {
        int n = send(s, (const char *)data, length > INT_MAX ? INT_MAX : (int)length, 0);
        if (n <= 0)
            return false;
        data += n;
        length -= (size_t)n;
    }
    return true;
}
static bool recv_all(SOCKET s, uint8_t *data, size_t length) {
    while (length) {
        int n = recv(s, (char *)data, length > INT_MAX ? INT_MAX : (int)length, 0);
        if (n <= 0)
            return false;
        data += n;
        length -= (size_t)n;
    }
    return true;
}
static SOCKET connect_control(const Config *c) {
    SOCKET s;
    struct sockaddr_in address;
    BOOL nodelay = TRUE;
    DWORD timeout = c->timeout_ms;
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return s;
    (void)setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay));
    (void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    (void)setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(c->ra_port);
    address.sin_addr = c->server_addr;
    if (connect(s, (struct sockaddr *)&address, sizeof(address))) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

static bool hold_packet(Session *s, const uint8_t *bytes, UINT length,
                        const WINDIVERT_ADDRESS *address) {
    HeldPacket *held;
    if ((size_t)length > HELD_CAP - s->held_bytes)
        return false;
    held = (HeldPacket *)malloc(sizeof(*held) + length - 1u);
    if (!held)
        return false;
    held->next = NULL;
    held->length = length;
    held->address = *address;
    memcpy(held->bytes, bytes, length);
    if (s->held_tail)
        s->held_tail->next = held;
    else
        s->held_head = held;
    s->held_tail = held;
    s->held_bytes += length;
    s->row.held_packets++;
    return true;
}
static void free_held(Session *s) {
    HeldPacket *p = s->held_head;
    while (p) {
        HeldPacket *next = p->next;
        free(p);
        p = next;
    }
    s->held_head = s->held_tail = NULL;
    s->held_bytes = 0;
}

static void retain_deny_handle(Context *c, HANDLE handle) {
    EnterCriticalSection(&c->denied_lock);
    if (c->denied_count == c->denied_capacity) {
        size_t cap = c->denied_capacity ? c->denied_capacity * 2 : 16;
        HANDLE *next = (HANDLE *)realloc(c->denied_handles, cap * sizeof(HANDLE));
        if (next) {
            c->denied_handles = next;
            c->denied_capacity = cap;
        }
    }
    if (c->denied_count < c->denied_capacity) {
        c->denied_handles[c->denied_count++] = handle;
        handle = INVALID_HANDLE_VALUE;
    }
    LeaveCriticalSection(&c->denied_lock);
    if (handle != INVALID_HANDLE_VALUE)
        WinDivertClose(handle);
}

static void decide(Session *s, bool allowed, const char *error) {
    HANDLE drop = INVALID_HANDLE_VALUE;
    char drop_error[128] = {0};
    allowed = allowed && !guard_is_tripped();
    if (!allowed) {
        guard_trip();
        drop = divert_open(s->filter, -100, WINDIVERT_FLAG_DROP, drop_error, sizeof(drop_error));
        if (drop != INVALID_HANDLE_VALUE)
            retain_deny_handle(s->context, drop);
    }
    EnterCriticalSection(&s->lock);
    append_error(&s->row, drop_error);
    append_error(&s->row, error);
    s->allowed = allowed;
    s->row.decision_ns = now_ns();
    if (allowed) {
        HeldPacket *p = s->held_head;
        while (p) {
            if (guard_is_tripped()) {
                s->allowed = false;
                break;
            }
            if (divert_send(s->divert, p->bytes, p->length, &p->address))
                s->row.released_packets++;
            else {
                append_win_error(&s->row, "release held packet failed", GetLastError());
                s->allowed = false;
                break;
            }
            p = p->next;
        }
    }
    free_held(s);
    s->decision_done = true;
    WakeAllConditionVariable(&s->changed);
    LeaveCriticalSection(&s->lock);
    if (!s->allowed)
        guard_trip();
    (void)WinDivertShutdown(s->divert, WINDIVERT_SHUTDOWN_RECV);
}

static DWORD WINAPI control_worker(void *opaque) {
    WorkerArg *arg = (WorkerArg *)opaque;
    Context *c = arg->context;
    size_t worker_id = arg->worker_id;
    SOCKET control = INVALID_SOCKET;
    free(arg);
    for (;;) {
        Session *s = (Session *)queue_pop(&c->control_queue);
        uint8_t request[80], header[88], report[CSV_REPORT_SIZE], verdict[84];
        uint8_t lookup[64], local_key[64], response_key[64], nonce[8];
        char reason[160] = {0};
        bool ok = true, reused, verified = false;
        uint32_t status, report_len;
        if (!s)
            break;
        reused = control != INVALID_SOCKET;
        if (control == INVALID_SOCKET)
            control = connect_control(&c->config);
        EnterCriticalSection(&s->lock);
        s->row.control_worker = worker_id;
        s->row.control_reused = reused;
        s->row.request_start_ns = now_ns();
        memcpy(lookup, s->row.lookup_key, 64);
        LeaveCriticalSection(&s->lock);
        if (control == INVALID_SOCKET) {
            strcpy_s(reason, sizeof(reason), "connect RA control failed");
            ok = false;
        }
        if (ok &&
            BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            strcpy_s(reason, sizeof(reason), "nonce generation failed");
            ok = false;
        }
        memset(request, 0, sizeof(request));
        write_be32(request, RA_MAGIC);
        write_be16(request + 4, RA_VERSION);
        write_be16(request + 6, RA_REQUEST);
        memcpy(request + 8, lookup, 64);
        memcpy(request + 72, nonce, 8);
        if (ok && (!send_all(control, request, sizeof(request)) ||
                   !recv_all(control, header, sizeof(header)))) {
            strcpy_s(reason, sizeof(reason), "RA request/response I/O failed");
            ok = false;
        }
        if (ok && (read_be32(header) != RA_MAGIC || read_be16(header + 4) != RA_VERSION ||
                   read_be16(header + 6) != RA_RESPONSE)) {
            strcpy_s(reason, sizeof(reason), "invalid RA response header");
            ok = false;
        }
        if (ok) {
            status = read_be32(header + 8);
            report_len = read_be32(header + 12);
            memcpy(response_key, header + 24, 64);
            EnterCriticalSection(&s->lock);
            s->row.response_status = status;
            memcpy(s->row.response_report_key, response_key, 64);
            s->row.have_response_report_key = true;
            LeaveCriticalSection(&s->lock);
            if (status || report_len != CSV_REPORT_SIZE) {
                _snprintf_s(reason, sizeof(reason), _TRUNCATE, "RA status=%lu report_len=%lu",
                            (unsigned long)status, (unsigned long)report_len);
                ok = false;
            }
        }
        if (ok && !recv_all(control, report, sizeof(report))) {
            strcpy_s(reason, sizeof(reason), "RA report read failed");
            ok = false;
        }
        if (ok) {
            EnterCriticalSection(&s->lock);
            s->row.response_done_ns = now_ns();
            while (!s->row.have_local_serverhello_key) {
                if (!SleepConditionVariableCS(&s->changed, &s->lock, c->config.timeout_ms) &&
                    GetLastError() == ERROR_TIMEOUT) {
                    strcpy_s(reason, sizeof(reason), "timed out waiting for ServerHello");
                    ok = false;
                    break;
                }
            }
            if (ok)
                memcpy(local_key, s->row.local_serverhello_key, 64);
            LeaveCriticalSection(&s->lock);
        }
        if (ok) {
            EnterCriticalSection(&s->lock);
            s->row.key_match = !memcmp(local_key, response_key, 64);
            s->row.verify_start_ns = now_ns();
            LeaveCriticalSection(&s->lock);
            verified = !memcmp(local_key, response_key, 64) &&
                       verify_report(report, local_key, reason, sizeof(reason));
            EnterCriticalSection(&s->lock);
            s->row.report_verify = verified;
            s->row.verify_done_ns = now_ns();
            LeaveCriticalSection(&s->lock);
            memset(verdict, 0, sizeof(verdict));
            write_be32(verdict, RA_MAGIC);
            write_be16(verdict + 4, RA_VERSION);
            write_be16(verdict + 6, RA_VERDICT);
            write_be32(verdict + 8, verified ? 1u : 0u);
            memcpy(verdict + 12, nonce, 8);
            memcpy(verdict + 20, lookup, 64);
            if (!send_all(control, verdict, sizeof(verdict))) {
                strcpy_s(reason, sizeof(reason), "RA verdict send failed");
                ok = false;
            } else {
                EnterCriticalSection(&s->lock);
                s->row.remote_verdict_sent = true;
                LeaveCriticalSection(&s->lock);
            }
            if (!verified)
                ok = false;
        }
        if (!ok && control != INVALID_SOCKET) {
            closesocket(control);
            control = INVALID_SOCKET;
        }
        decide(s, ok, ok ? NULL : reason);
        SetEvent(s->control_done);
    }
    if (control != INVALID_SOCKET)
        closesocket(control);
    return 0;
}

typedef enum { ACTION_SEND, ACTION_HOLD, ACTION_DROP } Action;
static Action inspect_packet(Session *s, const uint8_t *packet, UINT length,
                             const WINDIVERT_ADDRESS *address, const PacketView *v, bool *submit,
                             bool *detach) {
    Action action = ACTION_SEND;
    bool had_lookup;
    *submit = false;
    *detach = false;
    EnterCriticalSection(&s->lock);
    s->row.packets_copied++;
    s->row.bytes_copied += length;
    had_lookup = s->row.have_lookup_key;
    if (v->outbound && v->payload_len) {
        if (!buffer_append(&s->client_tls, v->payload, v->payload_len))
            append_error(&s->row, "ClientHello buffer exceeded 256 KiB");
        else if (!s->row.have_lookup_key && find_hello_key(s->client_tls.data, s->client_tls.length,
                                                           true, s->row.lookup_key)) {
            s->row.have_lookup_key = true;
            s->row.client_hello_ns = now_ns();
            fprintf(stderr, "TCPRA_EVENT session=%zu event=client_hello client_port=%u\n", s->id,
                    s->flow.local_port);
            if (s->row.ra && !s->worker_started) {
                s->worker_started = true;
                *submit = true;
            }
        }
    } else if (!v->outbound && v->payload_len) {
        if (!buffer_append(&s->server_tls, v->payload, v->payload_len))
            append_error(&s->row, "ServerHello buffer exceeded 256 KiB");
        else if (!s->row.have_local_serverhello_key &&
                 find_hello_key(s->server_tls.data, s->server_tls.length, false,
                                s->row.local_serverhello_key)) {
            s->row.have_local_serverhello_key = true;
            s->row.server_hello_ns = now_ns();
            fprintf(stderr, "TCPRA_EVENT session=%zu event=server_hello client_port=%u\n", s->id,
                    s->flow.local_port);
            WakeAllConditionVariable(&s->changed);
            if (!s->row.ra) {
                s->allowed = true;
                s->decision_done = true;
                s->row.decision_ns = now_ns();
                *detach = true;
            }
        }
    }
    if (v->fin || v->rst) {
        s->fin_seen = true;
        s->row.closed_ns = now_ns();
    }

    if (s->row.ra && v->outbound && v->payload_len && had_lookup && !s->decision_done) {
        if (hold_packet(s, packet, length, address))
            action = ACTION_HOLD;
        else {
            append_error(&s->row, "held packet arena exceeded 32 MiB");
            action = ACTION_DROP;
        }
    } else if (s->row.ra && v->outbound && v->payload_len && s->decision_done && !s->allowed)
        action = ACTION_DROP;
    LeaveCriticalSection(&s->lock);
    return action;
}

static void finish_session(Session *s) {
    Context *c = s->context;
    WaitForSingleObject(s->control_done, INFINITE);
    EnterCriticalSection(&s->lock);
    if (!s->row.closed_ns)
        s->row.closed_ns = now_ns();
    s->row.success = s->decision_done && s->allowed && (!s->row.ra || s->row.remote_verdict_sent);
    s->row.verified = s->row.report_verify;
    c->rows[s->id] = s->row;
    LeaveCriticalSection(&s->lock);
    (void)guard_release(s->divert);
    WinDivertClose(s->divert);
    buffer_free(&s->client_tls);
    buffer_free(&s->server_tls);
    free_held(s);
    CloseHandle(s->control_done);
    DeleteCriticalSection(&s->lock);
    EnterCriticalSection(&c->completed_lock);
    c->completed++;
    if (c->completed == c->config.expected)
        SetEvent(c->all_complete);
    LeaveCriticalSection(&c->completed_lock);
    free(s);
}

static DWORD WINAPI flow_worker(void *opaque) {
    WorkerArg *arg = (WorkerArg *)opaque;
    Context *c = arg->context;
    uint8_t *packet = (uint8_t *)malloc(PACKET_CAP);
    free(arg);
    if (!packet)
        return 1;
    for (;;) {
        Session *s = (Session *)queue_pop(&c->flow_queue);
        if (!s)
            break;
        for (;;) {
            UINT length = 0;
            WINDIVERT_ADDRESS address;
            PacketView view;
            bool submit = false, detach = false;
            Action action;
            if (!WinDivertRecv(s->divert, packet, PACKET_CAP, &length, &address)) {
                DWORD code = GetLastError();
                if (code != ERROR_NO_DATA && code != ERROR_OPERATION_ABORTED) {
                    EnterCriticalSection(&s->lock);
                    append_win_error(&s->row, "WinDivertRecv failed", code);
                    LeaveCriticalSection(&s->lock);
                }
                break;
            }
            if (!packet_view(packet, length, &c->config, &view)) {
                (void)divert_send(s->divert, packet, length, &address);
                continue;
            }
            action = inspect_packet(s, packet, length, &address, &view, &submit, &detach);
            if (submit && !queue_push(&c->control_queue, s)) {
                decide(s, false, "control worker pool stopped");
                SetEvent(s->control_done);
            }
            if (action == ACTION_SEND && !divert_send(s->divert, packet, length, &address)) {
                EnterCriticalSection(&s->lock);
                append_win_error(&s->row, "WinDivertSend failed", GetLastError());
                LeaveCriticalSection(&s->lock);
            }
            if (detach)
                (void)WinDivertShutdown(s->divert, WINDIVERT_SHUTDOWN_RECV);
        }
        finish_session(s);
    }
    free(packet);
    return 0;
}

static Session *session_new(Context *c, size_t id, const FlowKey *flow, HANDLE handle,
                            const char *filter) {
    Session *s = (Session *)calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->context = c;
    s->id = id;
    s->flow = *flow;
    s->divert = handle;
    strcpy_s(s->filter, sizeof(s->filter), filter);
    InitializeCriticalSection(&s->lock);
    InitializeConditionVariable(&s->changed);
    s->control_done = CreateEventW(NULL, TRUE, !c->config.ra, NULL);
    if (!s->control_done) {
        DeleteCriticalSection(&s->lock);
        free(s);
        return NULL;
    }
    s->row.session = id;
    s->row.ra = c->config.ra;
    s->row.flow = *flow;
    s->row.opened_ns = now_ns();
    s->row.response_status = UINT32_MAX;
    s->row.control_worker = SIZE_MAX;
    return s;
}

static bool start_workers(Context *c) {
    size_t i;

    c->flow_worker_count = c->config.workers < 8 ? 8 : c->config.workers;
    c->flow_threads = (HANDLE *)calloc(c->flow_worker_count, sizeof(HANDLE));
    c->control_threads = (HANDLE *)calloc(c->config.workers, sizeof(HANDLE));
    if (!c->flow_threads || !c->control_threads)
        return false;
    for (i = 0; i < c->flow_worker_count; i++) {
        WorkerArg *fa = (WorkerArg *)malloc(sizeof(*fa));
        if (!fa)
            return false;
        fa->context = c;
        fa->worker_id = i;
        c->flow_threads[i] = CreateThread(NULL, 0, flow_worker, fa, 0, NULL);
        if (!c->flow_threads[i])
            return false;
    }
    for (i = 0; i < c->config.workers; i++) {
        WorkerArg *ca = (WorkerArg *)malloc(sizeof(*ca));
        if (!ca)
            return false;
        ca->context = c;
        ca->worker_id = i;
        c->control_threads[i] = CreateThread(NULL, 0, control_worker, ca, 0, NULL);
        if (!c->control_threads[i])
            return false;
    }
    return true;
}

static bool write_csv(const Context *c) {
    FILE *file = NULL;
    size_t i;
    if (fopen_s(&file, c->config.output, "wb") || !file)
        return false;
    fprintf(file,
            "session,mode,ra,success,verified,local_ip,server_ip,client_port,"
            "server_port,lookup_key,local_serverhello_key,response_report_key,opened_ns,"
            "client_hello_ns,server_hello_ns,request_start_ns,response_done_ns,verify_start_ns,"
            "verify_done_ns,decision_ns,closed_ns,decision_total_ns,packets_copied,bytes_copied,"
            "held_packets,released_packets,response_status,key_match,report_verify,"
            "remote_verdict_sent,control_worker,control_reused,error\r\n");
    for (i = 0; i < c->config.expected; i++) {
        const Row *r = &c->rows[i];
        char local[INET_ADDRSTRLEN], remote[INET_ADDRSTRLEN];
        char lookup[129] = {0}, local_key[129] = {0}, response_key[129] = {0};
        char clean[ERROR_CAP];
        uint64_t total =
            r->decision_ns >= r->client_hello_ns ? r->decision_ns - r->client_hello_ns : 0;
        size_t j;
        ip_text(r->flow.local_ip, local);
        ip_text(r->flow.remote_ip, remote);
        if (r->have_lookup_key)
            hex_encode(r->lookup_key, 64, lookup);
        if (r->have_local_serverhello_key)
            hex_encode(r->local_serverhello_key, 64, local_key);
        if (r->have_response_report_key)
            hex_encode(r->response_report_key, 64, response_key);
        strcpy_s(clean, sizeof(clean), r->error);
        for (j = 0; clean[j]; j++)
            if (clean[j] == ',' || clean[j] == '\r' || clean[j] == '\n')
                clean[j] = ' ';
        fprintf(file,
                "%zu,conditional-c,%s,%s,%s,%s,%s,%u,%u,%s,%s,%s,"
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ","
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%lu,%s,%s,%s,%zu,%s,%s\r\n",
                r->session, r->ra ? "true" : "false", r->success ? "true" : "false",
                r->verified ? "true" : "false", local, remote, r->flow.local_port,
                r->flow.remote_port, lookup, local_key, response_key, r->opened_ns,
                r->client_hello_ns, r->server_hello_ns, r->request_start_ns, r->response_done_ns,
                r->verify_start_ns, r->verify_done_ns, r->decision_ns, r->closed_ns, total,
                r->packets_copied, r->bytes_copied, r->held_packets, r->released_packets,
                (unsigned long)r->response_status, r->key_match ? "true" : "false",
                r->report_verify ? "true" : "false", r->remote_verdict_sent ? "true" : "false",
                r->control_worker, r->control_reused ? "true" : "false", clean);
    }
    fclose(file);
    return true;
}

static bool parse_size(const char *text, size_t *value) {
    char *end = NULL;
    unsigned long long v = _strtoui64(text, &end, 10);
    if (!*text || !end || *end || v > SIZE_MAX)
        return false;
    *value = (size_t)v;
    return true;
}
static const char *argument_value(int argc, char **argv, const char *name) {
    int i;
    for (i = 1; i + 1 < argc; i++)
        if (!strcmp(argv[i], name))
            return argv[i + 1];
    return NULL;
}
static bool parse_config(int argc, char **argv, Config *c) {
    const char *value;
    size_t parsed;
    memset(c, 0, sizeof(*c));
    c->main_port = 19443;
    c->ra_port = 19442;
    c->expected = 1;
    c->timeout_ms = 15000;
    c->workers = 4;
    value = argument_value(argc, argv, "--self-test-report");
    if (value) {
        c->self_test_report = value;
        return true;
    }
    value = argument_value(argc, argv, "--mode");
    if (!value || strcmp(value, "conditional"))
        return false;
    value = argument_value(argc, argv, "--ra");
    if (!value || (strcmp(value, "true") && strcmp(value, "false")))
        return false;
    c->ra = !strcmp(value, "true");
    value = argument_value(argc, argv, "--server-ip");
    if (!value || InetPtonA(AF_INET, value, &c->server_addr) != 1)
        return false;
    strcpy_s(c->server_ip, sizeof(c->server_ip), value);
    value = argument_value(argc, argv, "--main-port");
    if (value) {
        if (!parse_size(value, &parsed) || parsed > UINT16_MAX)
            return false;
        c->main_port = (uint16_t)parsed;
    }
    value = argument_value(argc, argv, "--ra-port");
    if (value) {
        if (!parse_size(value, &parsed) || parsed > UINT16_MAX)
            return false;
        c->ra_port = (uint16_t)parsed;
    }
    value = argument_value(argc, argv, "--expected");
    if (value && !parse_size(value, &c->expected))
        return false;
    value = argument_value(argc, argv, "--workers");
    if (value && !parse_size(value, &c->workers))
        return false;
    value = argument_value(argc, argv, "--timeout-ms");
    if (value) {
        if (!parse_size(value, &parsed) || parsed > MAXDWORD)
            return false;
        c->timeout_ms = (DWORD)parsed;
    }
    c->output = argument_value(argc, argv, "--output");
    return c->expected && c->workers && c->output;
}

static int self_test(const char *path) {
    FILE *file = NULL;
    uint8_t report[CSV_REPORT_SIZE], expected[64];
    char reason[160] = {0};
    size_t n;
    memcpy(expected, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 64);
    if (fopen_s(&file, path, "rb") || !file) {
        fprintf(stderr, "SELF_TEST_FAIL open=%s\n", path);
        return 1;
    }
    n = fread(report, 1, sizeof(report), file);
    fclose(file);
    if (n != sizeof(report) || !verify_report(report, expected, reason, sizeof(reason))) {
        fprintf(stderr, "SELF_TEST_FAIL valid_report reason=%s\n", reason);
        return 1;
    }
    expected[0] ^= 1;
    if (verify_report(report, expected, reason, sizeof(reason))) {
        fprintf(stderr, "SELF_TEST_FAIL wrong_binding_accepted\n");
        return 1;
    }
    expected[0] ^= 1;
    report[REPORT_SIGNATURE_OFFSET] ^= 1;
    if (verify_report(report, expected, reason, sizeof(reason))) {
        fprintf(stderr, "SELF_TEST_FAIL damaged_signature_accepted\n");
        return 1;
    }
    printf("TCPRA_C_SELF_TEST_OK valid=accepted wrong_binding=rejected "
           "damaged_signature=rejected\n");
    return 0;
}

static void close_thread_handles(HANDLE *threads, size_t count) {
    size_t i;
    if (!threads)
        return;
    for (i = 0; i < count; i++)
        if (threads[i])
            CloseHandle(threads[i]);
}

static int run_agent(const Config *config) {
    Context c;
    HANDLE discovery = INVALID_HANDLE_VALUE;
    char discovery_filter[512], error[160] = {0};
    uint8_t *packet = NULL;
    FlowKey *accepted_flows = NULL;
    uint32_t *accepted_isn = NULL;
    size_t discovered = 0, i, failures = 0;
    bool flow_queue_ready = false, control_queue_ready = false;
    bool locks_ready = false, workers_joined = false;
    int result = 1;
    memset(&c, 0, sizeof(c));
    c.config = *config;
    if (!queue_init(&c.flow_queue, QUEUE_CAP))
        goto cleanup;
    flow_queue_ready = true;
    if (!queue_init(&c.control_queue, QUEUE_CAP))
        goto cleanup;
    control_queue_ready = true;
    InitializeCriticalSection(&c.completed_lock);
    InitializeCriticalSection(&c.denied_lock);
    locks_ready = true;
    c.all_complete = CreateEventW(NULL, TRUE, FALSE, NULL);
    c.rows = (Row *)calloc(config->expected, sizeof(Row));
    if (!c.all_complete || !c.rows || !start_workers(&c)) {
        fprintf(stderr, "tcpra_agent_c: worker initialization failed\n");
        goto cleanup;
    }
    _snprintf_s(discovery_filter, sizeof(discovery_filter), _TRUNCATE,
                "outbound and ip and tcp and ip.DstAddr == %s and tcp.DstPort == %u "
                "and tcp.Syn and not tcp.Ack",
                config->server_ip, config->main_port);
    discovery = divert_open(discovery_filter, 1000, 0, error, sizeof(error));
    if (discovery == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "tcpra_agent_c: open discovery handle: %s\n", error);
        goto cleanup;
    }
    if (!guard_hold(discovery))
        goto cleanup;
    packet = (uint8_t *)malloc(PACKET_CAP);
    accepted_flows = (FlowKey *)calloc(config->expected, sizeof(FlowKey));
    accepted_isn = (uint32_t *)calloc(config->expected, sizeof(uint32_t));
    if (!packet || !accepted_flows || !accepted_isn)
        goto cleanup;
    printf("TCPRA_AGENT_READY mode=conditional-c ra=%s expected=%zu\n",
           config->ra ? "true" : "false", config->expected);
    fflush(stdout);
    while (discovered < config->expected) {
        UINT length = 0;
        WINDIVERT_ADDRESS address;
        PacketView view;
        char exact[768], open_error[160] = {0};
        HANDLE handle;
        Session *s;
        bool duplicate = false;
        if (!WinDivertRecv(discovery, packet, PACKET_CAP, &length, &address)) {
            fprintf(stderr, "tcpra_agent_c: discovery receive failed (winerr=%lu)\n",
                    (unsigned long)GetLastError());
            goto cleanup;
        }
        if (!packet_view(packet, length, config, &view) || !view.outbound || !view.syn ||
            view.ack) {
            if (!divert_send(discovery, packet, length, &address))
                goto cleanup;
            continue;
        }
        for (i = 0; i < discovered; i++) {
            if (!memcmp(&accepted_flows[i], &view.flow, sizeof(view.flow))) {

                if (accepted_isn[i] != view.sequence) {
                    guard_trip();
                    goto cleanup;
                }
                duplicate = true;
                break;
            }
        }
        if (duplicate) {

            if (!divert_send(discovery, packet, length, &address))
                goto cleanup;
            continue;
        }
        exact_filter(&view.flow, exact, sizeof(exact));
        handle = divert_open(exact, 0, 0, open_error, sizeof(open_error));
        if (handle == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "tcpra_agent_c: open per-flow handle: %s\n", open_error);
            goto cleanup;
        }
        if (!guard_hold(handle)) {
            WinDivertClose(handle);
            goto cleanup;
        }
        s = session_new(&c, discovered, &view.flow, handle, exact);
        if (!s || !queue_push(&c.flow_queue, s)) {
            guard_trip();
            if (!s) {
                (void)guard_release(handle);
                WinDivertClose(handle);
            }
            fprintf(stderr, "tcpra_agent_c: enqueue flow failed\n");
            goto cleanup;
        }
        if (!divert_send(discovery, packet, length, &address)) {
            fprintf(stderr, "tcpra_agent_c: reinject SYN failed (winerr=%lu)\n",
                    (unsigned long)GetLastError());
            goto cleanup;
        }
        accepted_flows[discovered] = view.flow;
        accepted_isn[discovered] = view.sequence;
        fprintf(stderr, "TCPRA_EVENT session=%zu event=flow_open client_port=%u\n", discovered,
                view.flow.local_port);
        discovered++;
    }
    (void)guard_release(discovery);
    WinDivertClose(discovery);
    discovery = INVALID_HANDLE_VALUE;
    WaitForSingleObject(c.all_complete, INFINITE);
    queue_close(&c.flow_queue);
    queue_close(&c.control_queue);

    for (i = 0; i < c.flow_worker_count; i++) {
        WaitForSingleObject(c.flow_threads[i], INFINITE);
    }
    for (i = 0; i < config->workers; i++) {
        WaitForSingleObject(c.control_threads[i], INFINITE);
    }
    workers_joined = true;
    if (!write_csv(&c)) {
        fprintf(stderr, "tcpra_agent_c: failed to write %s\n", config->output);
        goto cleanup;
    }
    for (i = 0; i < config->expected; i++)
        if (!c.rows[i].success)
            failures++;
    printf("TCPRA_AGENT_DONE sessions=%zu failures=%zu output=%s\n", config->expected, failures,
           config->output);
    result = failures ? 1 : 0;
cleanup:
    if (result != 0)
        guard_trip();
    free(packet);
    free(accepted_flows);
    free(accepted_isn);
    if (discovery != INVALID_HANDLE_VALUE) {
        (void)guard_release(discovery);
        WinDivertClose(discovery);
    }
    if (flow_queue_ready)
        queue_close(&c.flow_queue);
    if (control_queue_ready)
        queue_close(&c.control_queue);

    if (!workers_joined) {

        ExitProcess(3);
    }
    close_thread_handles(c.flow_threads, c.flow_worker_count);
    close_thread_handles(c.control_threads, config->workers);
    for (i = 0; i < c.denied_count; i++)
        WinDivertClose(c.denied_handles[i]);
    free(c.denied_handles);
    free(c.flow_threads);
    free(c.control_threads);
    free(c.rows);
    if (c.all_complete)
        CloseHandle(c.all_complete);
    if (locks_ready) {
        DeleteCriticalSection(&c.completed_lock);
        DeleteCriticalSection(&c.denied_lock);
    }
    if (flow_queue_ready)
        queue_destroy(&c.flow_queue);
    if (control_queue_ready)
        queue_destroy(&c.control_queue);
    if (result == 0 && !guard_done())
        result = 3;
    return result;
}

int main(int argc, char **argv) {
    Config config;
    WSADATA winsock;
    int result;
    if (!parse_config(argc, argv, &config)) {
        fprintf(stderr, "usage: tcpra_agent_c --mode conditional --ra true|false --server-ip IP "
                        "[--main-port 19443] [--ra-port 19442] [--expected N] [--workers N] "
                        "[--timeout-ms N] --output FILE\n"
                        "       tcpra_agent_c --self-test-report valid-report.bin\n");
        return 2;
    }
    uint8_t configured_pek[64], configured_measurement[32];
    if (!hex_decode(TRUSTED_PEK_HEX, configured_pek, sizeof configured_pek) ||
        !hex_decode(TRUSTED_MEASUREMENT_HEX, configured_measurement,
                    sizeof configured_measurement)) {
        fprintf(stderr, "CSV trust configuration is missing or invalid\n");
        return 2;
    }
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) {
        fprintf(stderr, "tcpra_agent_c: WSAStartup failed\n");
        return 1;
    }
    if (!config.self_test_report &&
        !guard_worker_init(argc, argv, config.server_ip, config.main_port)) {
        fprintf(stderr, "Worker requires the lightweight guardian launcher\n");
        WSACleanup();
        return 2;
    }
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    result = config.self_test_report ? self_test(config.self_test_report) : run_agent(&config);
    WSACleanup();
    return result;
}
