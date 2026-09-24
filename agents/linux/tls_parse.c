#include <arpa/inet.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>

#include "tls_parse.h"

static int digest_share(const char *label, const uint8_t *data, size_t length,
                        uint8_t out[RA_KEY_SIZE]) {
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned int output_length = 0;
    int ok = context && EVP_DigestInit_ex(context, EVP_sha512(), NULL) == 1 &&
             EVP_DigestUpdate(context, label, strlen(label)) == 1 &&
             EVP_DigestUpdate(context, data, length) == 1 &&
             EVP_DigestFinal_ex(context, out, &output_length) == 1 && output_length == RA_KEY_SIZE;
    EVP_MD_CTX_free(context);
    return ok;
}

int tcpra_client_lookup_from_key_share(const uint8_t *extension, size_t extension_length,
                                       uint8_t out[RA_KEY_SIZE]) {
    if (!extension || extension_length < 6 || !out)
        return 0;
    size_t shares = ((size_t)extension[0] << 8) | extension[1];
    if (shares + 2 != extension_length || shares < 4)
        return 0;
    return digest_share("tcp-level-ra/clienthello-key/v1", extension, extension_length, out);
}

int tcpra_extract_clienthello_lookup(const uint8_t *buffer, size_t length,
                                     uint8_t out[RA_KEY_SIZE]) {
    if (length < 4 || buffer[0] != 1)
        return 0;
    size_t body = ((size_t)buffer[1] << 16) | ((size_t)buffer[2] << 8) | buffer[3];
    if (body + 4 > length || body < 34)
        return 0;
    size_t offset = 4 + 2 + 32;
    if (offset >= length)
        return 0;
    size_t session_id = buffer[offset++];
    if (offset + session_id + 2 > length)
        return 0;
    offset += session_id;
    size_t suites = ((size_t)buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    if (offset + suites + 1 > length)
        return 0;
    offset += suites;
    size_t compression = buffer[offset++];
    if (offset + compression + 2 > length)
        return 0;
    offset += compression;
    size_t extensions_end = offset + 2 + (((size_t)buffer[offset] << 8) | buffer[offset + 1]);
    offset += 2;
    if (extensions_end > length)
        return 0;
    while (offset + 4 <= extensions_end) {
        uint16_t type = ((uint16_t)buffer[offset] << 8) | buffer[offset + 1];
        size_t extension_length = ((size_t)buffer[offset + 2] << 8) | buffer[offset + 3];
        offset += 4;
        if (offset + extension_length > extensions_end)
            return 0;
        if (type == 51 && extension_length >= 6) {
            return tcpra_client_lookup_from_key_share(buffer + offset, extension_length, out);
        }
        offset += extension_length;
    }
    return 0;
}

int tcpra_report_key_from_public(uint16_t group_id, const uint8_t *public_key,
                                 size_t public_key_length, uint8_t report_key[RA_KEY_SIZE]) {
    if (!public_key || public_key_length == 0 || public_key_length > 128)
        return 0;
    uint8_t extension[4 + TCPRA_MAX_PUBLIC_KEY];
    uint16_t network_group = htons(group_id);
    uint16_t network_length = htons((uint16_t)public_key_length);
    memcpy(extension, &network_group, sizeof(network_group));
    memcpy(extension + 2, &network_length, sizeof(network_length));
    memcpy(extension + 4, public_key, public_key_length);
    return digest_share("tcp-level-ra/serverhello-key/v1", extension, public_key_length + 4,
                        report_key);
}

int tcpra_early_client_report_key(const uint8_t lookup_key[RA_KEY_SIZE],
                                  uint64_t network_client_nonce,
                                  uint8_t client_report_key[RA_KEY_SIZE]) {
    static const char label[] = "tcp-level-ra/mutual-client-early/v2";
    if (!lookup_key || !client_report_key)
        return 0;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned int output_length = 0;
    int ok = context && EVP_DigestInit_ex(context, EVP_sha512(), NULL) == 1 &&
             EVP_DigestUpdate(context, label, sizeof(label) - 1) == 1 &&
             EVP_DigestUpdate(context, lookup_key, RA_KEY_SIZE) == 1 &&
             EVP_DigestUpdate(context, &network_client_nonce, sizeof(network_client_nonce)) == 1 &&
             EVP_DigestFinal_ex(context, client_report_key, &output_length) == 1 &&
             output_length == RA_KEY_SIZE;
    EVP_MD_CTX_free(context);
    return ok;
}

int tcpra_early_server_report_key(const uint8_t server_hello_key[RA_KEY_SIZE],
                                  const uint8_t client_report_key[RA_KEY_SIZE],
                                  uint8_t server_report_key[RA_KEY_SIZE]) {
    static const char label[] = "tcp-level-ra/mutual-server-early/v2";
    if (!server_hello_key || !client_report_key || !server_report_key)
        return 0;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned int output_length = 0;
    int ok = context && EVP_DigestInit_ex(context, EVP_sha512(), NULL) == 1 &&
             EVP_DigestUpdate(context, label, sizeof(label) - 1) == 1 &&
             EVP_DigestUpdate(context, server_hello_key, RA_KEY_SIZE) == 1 &&
             EVP_DigestUpdate(context, client_report_key, RA_KEY_SIZE) == 1 &&
             EVP_DigestFinal_ex(context, server_report_key, &output_length) == 1 &&
             output_length == RA_KEY_SIZE;
    EVP_MD_CTX_free(context);
    return ok;
}

int tcpra_extract_serverhello(const uint8_t *buffer, size_t length, uint16_t *group_id,
                              uint8_t public_key[128], size_t *public_key_length,
                              uint8_t report_key[RA_KEY_SIZE]) {
    if (length < 4 || buffer[0] != 2)
        return 0;
    size_t body = ((size_t)buffer[1] << 16) | ((size_t)buffer[2] << 8) | buffer[3];
    if (body + 4 > length || body < 38)
        return 0;
    size_t offset = 4 + 2 + 32;
    if (offset >= length)
        return 0;
    size_t session_id = buffer[offset++];
    if (offset + session_id + 3 > length)
        return 0;
    offset += session_id + 2 + 1;
    if (offset + 2 > length)
        return 0;
    size_t extensions_end = offset + 2 + (((size_t)buffer[offset] << 8) | buffer[offset + 1]);
    offset += 2;
    if (extensions_end > length)
        return 0;
    while (offset + 4 <= extensions_end) {
        uint16_t type = ((uint16_t)buffer[offset] << 8) | buffer[offset + 1];
        size_t extension_length = ((size_t)buffer[offset + 2] << 8) | buffer[offset + 3];
        offset += 4;
        if (offset + extension_length > extensions_end)
            return 0;
        if (type == 51 && extension_length >= 4) {
            size_t key_length = ((size_t)buffer[offset + 2] << 8) | buffer[offset + 3];
            if (key_length == 0 || key_length > 128 || key_length + 4 != extension_length)
                return 0;
            *group_id = ((uint16_t)buffer[offset] << 8) | buffer[offset + 1];
            *public_key_length = key_length;
            memcpy(public_key, buffer + offset + 4, key_length);
            return digest_share("tcp-level-ra/serverhello-key/v1", buffer + offset,
                                extension_length, report_key);
        }
        offset += extension_length;
    }
    return 0;
}

static int find_handshake(const uint8_t *data, size_t length, uint8_t wanted,
                          uint8_t lookup_key[RA_KEY_SIZE], uint16_t *group_id,
                          uint8_t public_key[128], size_t *public_key_length,
                          uint8_t report_key[RA_KEY_SIZE]) {
    size_t offset = 0;
    while (offset + 5 <= length) {
        uint8_t content_type = data[offset];
        size_t record_length = ((size_t)data[offset + 3] << 8) | data[offset + 4];
        if (offset + 5 + record_length > length)
            break;
        if (content_type == 22) {
            size_t position = offset + 5;
            size_t end = position + record_length;
            while (position + 4 <= end) {
                size_t handshake_length = ((size_t)data[position + 1] << 16) |
                                          ((size_t)data[position + 2] << 8) | data[position + 3];
                if (position + 4 + handshake_length > end)
                    break;
                if (data[position] == wanted) {
                    if (wanted == 1)
                        return tcpra_extract_clienthello_lookup(data + position,
                                                                4 + handshake_length, lookup_key);
                    return tcpra_extract_serverhello(data + position, 4 + handshake_length,
                                                     group_id, public_key, public_key_length,
                                                     report_key);
                }
                position += 4 + handshake_length;
            }
        }
        offset += 5 + record_length;
    }
    return 0;
}

int tcpra_tls_find_clienthello(const uint8_t *data, size_t length,
                               uint8_t lookup_key[RA_KEY_SIZE]) {
    return find_handshake(data, length, 1, lookup_key, NULL, NULL, NULL, NULL);
}

int tcpra_tls_find_serverhello(const uint8_t *data, size_t length, uint16_t *group_id,
                               uint8_t public_key[128], size_t *public_key_length,
                               uint8_t report_key[RA_KEY_SIZE]) {
    return find_handshake(data, length, 2, NULL, group_id, public_key, public_key_length,
                          report_key);
}

int tcpra_tls_contains_encrypted_record(const uint8_t *data, size_t length) {
    size_t offset = 0;
    while (offset + 5 <= length) {
        size_t record_length = ((size_t)data[offset + 3] << 8) | data[offset + 4];
        if (offset + 5 + record_length > length)
            break;
        if (data[offset] == 23 && record_length > 0)
            return 1;
        offset += 5 + record_length;
    }
    return 0;
}
