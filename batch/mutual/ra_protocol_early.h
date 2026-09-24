#ifndef RA_PROTOCOL_EARLY_H
#define RA_PROTOCOL_EARLY_H

#include <stdint.h>

#define RA_MAGIC 0x43535631u
#define RA_VERSION 5u
#define RA_MRA_VERSION 6u
#define RA_REPORT_SIZE 2548u
#define RA_KEY_SIZE 64u
#define RA_WINDOW_NS (30ull * 1000000000ull)

enum {
    RA_REQUEST = 1,
    RA_RESPONSE = 2,
    RA_VERDICT = 3,
    RA_MUTUAL_REQUEST = 4,
};

struct __attribute__((packed)) ra_request {
    uint32_t magic;
    uint16_t version;
    uint16_t type;

    uint8_t lookup_key[RA_KEY_SIZE];
    uint64_t client_nonce;
};

struct __attribute__((packed)) ra_response {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t status;
    uint32_t report_len;
    uint64_t generated_ns;

    uint8_t report_key[RA_KEY_SIZE];
};

struct __attribute__((packed)) ra_verdict {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t verified;
    uint64_t client_nonce;

    uint8_t lookup_key[RA_KEY_SIZE];
};

_Static_assert(sizeof(struct ra_request) == 80, "unexpected RA request wire size");
_Static_assert(sizeof(struct ra_response) == 88, "unexpected RA response wire size");
_Static_assert(sizeof(struct ra_verdict) == 84, "unexpected RA verdict wire size");

enum {
    RA_OK = 0,
    RA_NOT_FOUND = 1,
    RA_EXPIRED = 2,
    RA_BAD_BINDING = 3,
    RA_INTERNAL = 4,
    RA_CLIENT_REPORT_INVALID = 5
};

#endif
