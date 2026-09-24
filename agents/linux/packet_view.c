#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#include "packet_view.h"

int tcpra_parse_ipv4_tcp(const uint8_t *packet, size_t length, struct tcpra_ipv4_tcp_view *view) {
    if (!packet || !view || length < 40 || (packet[0] >> 4) != 4 || packet[9] != IPPROTO_TCP)
        return 0;
    size_t ip_header = (size_t)(packet[0] & 0x0f) * 4u;
    if (ip_header < 20 || length < ip_header + 20)
        return 0;
    uint16_t fragment;
    memcpy(&fragment, packet + 6, sizeof(fragment));
    if ((ntohs(fragment) & 0x1fff) != 0)
        return 0;
    size_t tcp_header = (size_t)((packet[ip_header + 12] >> 4) & 0x0f) * 4u;
    if (tcp_header < 20 || length < ip_header + tcp_header)
        return 0;
    uint16_t source_port, destination_port;
    memcpy(&view->source, packet + 12, sizeof(view->source));
    memcpy(&view->destination, packet + 16, sizeof(view->destination));
    memcpy(&source_port, packet + ip_header, sizeof(source_port));
    memcpy(&destination_port, packet + ip_header + 2, sizeof(destination_port));
    view->source_port = ntohs(source_port);
    view->destination_port = ntohs(destination_port);
    view->tcp_flags = packet[ip_header + 13];
    memcpy(&view->sequence, packet + ip_header + 4, sizeof(view->sequence));
    view->sequence = ntohl(view->sequence);
    view->raw_sequence = view->sequence;
    memcpy(&view->acknowledgement, packet + ip_header + 8, sizeof(view->acknowledgement));
    view->acknowledgement = ntohl(view->acknowledgement);
    view->payload = packet + ip_header + tcp_header;
    view->payload_length = length - ip_header - tcp_header;
    view->sequence += (uint32_t)tcp_header;
    return 1;
}

int tcpra_normalize_flow(const struct tcpra_ipv4_tcp_view *view, uint16_t server_port,
                         struct flow_key *flow, int *client_to_server) {
    if (view->destination_port == server_port) {
        flow->client_ip = view->source;
        flow->server_ip = view->destination;
        flow->client_port = view->source_port;
        flow->server_port = view->destination_port;
        *client_to_server = 1;
        return 1;
    }
    if (view->source_port == server_port) {
        flow->client_ip = view->destination;
        flow->server_ip = view->source;
        flow->client_port = view->destination_port;
        flow->server_port = view->source_port;
        *client_to_server = 0;
        return 1;
    }
    return 0;
}
