#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "csv_attestation.h"

typedef struct __attribute__((packed)) {
    uint8_t bytes[32];
} Hash;
typedef struct __attribute__((packed)) {
    uint32_t curve;
    uint32_t x[18];
    uint32_t y[18];
    uint32_t uid[64];
} Point72;
typedef struct __attribute__((packed)) {
    uint32_t r[18];
    uint32_t s[18];
} Sig72;
typedef struct __attribute__((packed)) {
    uint32_t version;
    uint8_t api_major, api_minor, reserved1, reserved2;
    uint32_t pubkey_usage, pubkey_algo;
    Point72 pubkey;
    uint32_t reserved3[156];
    uint32_t sig1_usage, sig1_algo;
    Sig72 sig1;
    uint32_t reserved4[92];
    uint32_t sig2_usage, sig2_algo;
    Sig72 sig2;
    uint32_t reserved5[92];
} CsvCert;
typedef struct __attribute__((packed)) {
    Hash user_pubkey_digest;
    uint8_t vm_id[16], vm_version[16], user_data[64], mnonce[16];
    Hash measure;
    uint32_t policy, sig_usage, sig_algo, anonce;
    Sig72 sig1;
    CsvCert pek;
    uint8_t sn[64], reserved2[32];
    Hash mac;
} Report;
typedef struct __attribute__((packed)) {
    uint32_t curve;
    uint8_t x[32], y[32];
} VerifyPoint;
typedef struct __attribute__((packed)) {
    uint8_t r[32], s[32];
} VerifySig;

_Static_assert(sizeof(Report) == RA_REPORT_SIZE,
               "CSV report layout no longer matches the wire size");

static int hex_decode(const char *text, uint8_t *output, size_t length) {
    if (!text || strlen(text) != length * 2 || strspn(text, "0123456789abcdefABCDEF") != length * 2)
        return 0;
    for (size_t index = 0; index < length; index++) {
        unsigned value;
        if (sscanf(text + index * 2, "%2x", &value) != 1)
            return 0;
        output[index] = (uint8_t)value;
    }
    return 1;
}

static void xor_words(const uint8_t *input, size_t length, uint32_t nonce, uint8_t *output) {
    for (size_t index = 0; index < length / sizeof(uint32_t); index++) {
        uint32_t word;
        memcpy(&word, input + index * sizeof(word), sizeof(word));
        word ^= nonce;
        memcpy(output + index * sizeof(word), &word, sizeof(word));
    }
}

static int csv_debug(void) {
    static int cached = -1;
    if (cached < 0)
        cached = getenv("CSV_RA_DEBUG") != NULL;
    return cached;
}
#define CSV_DBG(...)                                                                               \
    do {                                                                                           \
        if (csv_debug())                                                                           \
            fprintf(stderr, "csv_debug: " __VA_ARGS__);                                            \
    } while (0)

int tcpra_csv_context_open(struct tcpra_csv_context *context, int reporter) {
    memset(context, 0, sizeof(*context));
    const char *path = getenv("CSV_RA_LIB");
    if (!path || !*path)
        path = "libcsv.so";
    context->handle = dlmopen(LM_ID_NEWLM, path, RTLD_NOW | RTLD_LOCAL);
    if (!context->handle) {
        fprintf(stderr, "dlmopen(%s): %s\n", path, dlerror());
        return 0;
    }
    void *verify_symbol = dlsym(context->handle, "gmssl_sm2_verify");
    void *report_symbol =
        reporter ? dlsym(context->handle, "vmmcall_get_attestation_report") : NULL;
    _Static_assert(sizeof(verify_symbol) == sizeof(context->sm2_verify),
                   "function and object pointers differ");
    _Static_assert(sizeof(report_symbol) == sizeof(context->get_report),
                   "function and object pointers differ");
    memcpy(&context->sm2_verify, &verify_symbol, sizeof(verify_symbol));
    memcpy(&context->get_report, &report_symbol, sizeof(report_symbol));
    if (!context->sm2_verify || (reporter && !context->get_report) ||
        !hex_decode(getenv("CSV_RA_TRUSTED_PEK"), context->trusted_pek,
                    sizeof(context->trusted_pek)) ||
        !hex_decode(getenv("CSV_RA_TRUSTED_MEASURE"), context->trusted_measurement,
                    sizeof(context->trusted_measurement))) {
        fprintf(stderr, "invalid CSV library or trust configuration\n");
        dlclose(context->handle);
        memset(context, 0, sizeof(*context));
        return 0;
    }
    context->reporter = reporter != 0;
    pthread_mutex_init(&context->library_mutex, NULL);
    return 1;
}

void tcpra_csv_context_close(struct tcpra_csv_context *context) {
    if (!context || !context->handle)
        return;
    pthread_mutex_destroy(&context->library_mutex);
    dlclose(context->handle);
    memset(context, 0, sizeof(*context));
}

int tcpra_csv_verify_report(struct tcpra_csv_context *context, const uint8_t bytes[RA_REPORT_SIZE],
                            const uint8_t expected[RA_KEY_SIZE]) {
    if (!context || !context->sm2_verify || !bytes || !expected)
        return 0;
    uint32_t nonce;
    memcpy(&nonce, bytes + offsetof(Report, anonce), sizeof(nonce));
    uint8_t user_data[RA_KEY_SIZE];
    xor_words(bytes + offsetof(Report, user_data), sizeof(user_data), nonce, user_data);
    if (memcmp(user_data, expected, sizeof(user_data)) != 0) {
        CSV_DBG("verify fail: user_data mismatch (nonce=%u)\n", nonce);
        return 0;
    }

    CsvCert pek;
    xor_words(bytes + offsetof(Report, pek), sizeof(pek), nonce, (uint8_t *)&pek);
    const uint8_t *pek_bytes = (const uint8_t *)&pek;
    size_t point_offset = offsetof(CsvCert, pubkey);
    size_t x_offset = point_offset + offsetof(Point72, x);
    size_t y_offset = point_offset + offsetof(Point72, y);
    size_t uid_offset = point_offset + offsetof(Point72, uid);
    VerifyPoint point;
    memset(&point, 0, sizeof(point));
    memcpy(&point.curve, pek_bytes + point_offset + offsetof(Point72, curve), sizeof(point.curve));
    for (size_t index = 0; index < 32; index++) {
        point.x[index] = pek_bytes[x_offset + 31 - index];
        point.y[index] = pek_bytes[y_offset + 31 - index];
    }
    uint16_t uid_length;
    memcpy(&uid_length, pek_bytes + uid_offset, sizeof(uid_length));
    if (uid_length > 254)
        return 0;
    VerifySig signature;
    memcpy(signature.r, bytes + offsetof(Report, sig1) + offsetof(Sig72, r), sizeof(signature.r));
    memcpy(signature.s, bytes + offsetof(Report, sig1) + offsetof(Sig72, s), sizeof(signature.s));
    pthread_mutex_lock(&context->library_mutex);
    int signature_ok = context->sm2_verify(
                           &point, (int)sizeof(point), (void *)(pek_bytes + uid_offset + 2),
                           uid_length, (void *)bytes, 180, &signature, (int)sizeof(signature)) == 0;
    pthread_mutex_unlock(&context->library_mutex);
    if (!signature_ok) {
        CSV_DBG("verify fail: sm2 signature (uid_length=%u)\n", uid_length);
        return 0;
    }
    uint8_t actual_pek[64];
    for (size_t index = 0; index < 32; index++) {
        actual_pek[index] = pek_bytes[x_offset + 31 - index];
        actual_pek[32 + index] = pek_bytes[y_offset + 31 - index];
    }
    if (memcmp(actual_pek, context->trusted_pek, sizeof(actual_pek)) != 0) {
        if (csv_debug()) {
            fprintf(stderr, "csv_debug: verify fail: pek mismatch\n  actual  :");
            for (size_t i = 0; i < sizeof(actual_pek); i++)
                fprintf(stderr, "%02x", actual_pek[i]);
            fprintf(stderr, "\n  trusted :");
            for (size_t i = 0; i < sizeof(context->trusted_pek); i++)
                fprintf(stderr, "%02x", context->trusted_pek[i]);
            fprintf(stderr, "\n  vm_id   :");
            for (size_t i = 0; i < 16; i++)
                fprintf(stderr, "%02x", bytes[offsetof(Report, vm_id) + i]);
            fprintf(stderr, "\n  measured:");
            {
                uint32_t nonce2;
                memcpy(&nonce2, bytes + offsetof(Report, anonce), sizeof(nonce2));
                uint8_t measurement_dump[32];
                xor_words(bytes + offsetof(Report, measure), sizeof(measurement_dump), nonce2,
                          measurement_dump);
                for (size_t i = 0; i < 32; i++)
                    fprintf(stderr, "%02x", measurement_dump[i]);
            }
            fprintf(stderr, "\n");
        }
        return 0;
    }
    uint8_t measurement[32];
    xor_words(bytes + offsetof(Report, measure), sizeof(measurement), nonce, measurement);
    if (memcmp(measurement, context->trusted_measurement, sizeof(measurement)) != 0) {
        CSV_DBG("verify fail: measurement mismatch (nonce=%u)\n", nonce);
        return 0;
    }
    return 1;
}

int tcpra_csv_generate_report(struct tcpra_csv_context *context, const uint8_t key[RA_KEY_SIZE],
                              uint8_t report[RA_REPORT_SIZE]) {
    if (!context || !context->reporter || !context->get_report) {
        CSV_DBG("generate fail: context not open\n");
        return 0;
    }
    pthread_mutex_lock(&context->library_mutex);
    int rc = context->get_report((void *)key, RA_KEY_SIZE, report, RA_REPORT_SIZE);
    pthread_mutex_unlock(&context->library_mutex);
    if (rc != 0) {
        CSV_DBG("generate fail: get_report rc=%d\n", rc);
        return 0;
    }
    return tcpra_csv_verify_report(context, report, key);
}
