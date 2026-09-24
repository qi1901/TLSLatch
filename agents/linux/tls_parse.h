#ifndef TCPRA_TLS_PARSE_H
#define TCPRA_TLS_PARSE_H

#include <stddef.h>
#include <stdint.h>

#include "ra_protocol_early.h"

#define TCPRA_MAX_PUBLIC_KEY 128u

int tcpra_extract_clienthello_lookup(const uint8_t *message, size_t length,
                                     uint8_t out[RA_KEY_SIZE]);
int tcpra_client_lookup_from_key_share(const uint8_t *extension, size_t extension_length,
                                       uint8_t out[RA_KEY_SIZE]);
int tcpra_extract_serverhello(const uint8_t *message, size_t length, uint16_t *group_id,
                              uint8_t public_key[128], size_t *public_key_length,
                              uint8_t report_key[RA_KEY_SIZE]);
int tcpra_tls_find_clienthello(const uint8_t *data, size_t length, uint8_t lookup_key[RA_KEY_SIZE]);
int tcpra_tls_find_serverhello(const uint8_t *data, size_t length, uint16_t *group_id,
                               uint8_t public_key[128], size_t *public_key_length,
                               uint8_t report_key[RA_KEY_SIZE]);
int tcpra_tls_contains_encrypted_record(const uint8_t *data, size_t length);
int tcpra_report_key_from_public(uint16_t group_id, const uint8_t *public_key,
                                 size_t public_key_length, uint8_t report_key[RA_KEY_SIZE]);
int tcpra_early_client_report_key(const uint8_t lookup_key[RA_KEY_SIZE],
                                  uint64_t network_client_nonce,
                                  uint8_t client_report_key[RA_KEY_SIZE]);
int tcpra_early_server_report_key(const uint8_t server_hello_key[RA_KEY_SIZE],
                                  const uint8_t client_report_key[RA_KEY_SIZE],
                                  uint8_t server_report_key[RA_KEY_SIZE]);

#endif
