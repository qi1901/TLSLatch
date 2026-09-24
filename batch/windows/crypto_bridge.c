#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
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

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint16_t read_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
#define TRUSTED_PEK_HEX getenv("CSV_RA_TRUSTED_PEK")
#define TRUSTED_MEASUREMENT_HEX getenv("CSV_RA_TRUSTED_MEASURE")
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

int csv_verify_init(void) {
    uint8_t p[64], m[32];
    return hex_decode(TRUSTED_PEK_HEX, p, 64) && hex_decode(TRUSTED_MEASUREMENT_HEX, m, 32);
}
int csv_verify_binding(const unsigned char *r, const unsigned char *b) {
    char reason[128];
    return verify_report(r, b, reason, sizeof reason);
}
