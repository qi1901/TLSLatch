#ifndef TCPRA_UNIFIED_PACKET_VIEW_H
#define TCPRA_UNIFIED_PACKET_VIEW_H

#include <stddef.h>
#include <stdint.h>

#include "flow_gate.h"

struct tcpra_ipv4_tcp_view {
    uint32_t source;
    uint32_t destination;
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t tcp_flags;
    uint32_t raw_sequence, acknowledgement;
    uint32_t sequence;
    const uint8_t *payload;
    size_t payload_length;
};

int tcpra_parse_ipv4_tcp(const uint8_t *packet, size_t length, struct tcpra_ipv4_tcp_view *view);
int tcpra_normalize_flow(const struct tcpra_ipv4_tcp_view *view, uint16_t server_port,
                         struct flow_key *flow, int *client_to_server);

#endif
