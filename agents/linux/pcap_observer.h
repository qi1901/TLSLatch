#ifndef TCPRA_PCAP_OBSERVER_H
#define TCPRA_PCAP_OBSERVER_H

#include <stddef.h>
#include <stdint.h>

#include "flow_gate.h"

struct tcpra_pcap_observer;

typedef int (*tcpra_pcap_key_callback)(void *opaque, const struct flow_key *flow, uint16_t group_id,
                                       const uint8_t *public_key, size_t public_key_length,
                                       uint64_t observed_ns, uint64_t socket_cookie);

typedef int (*tcpra_pcap_lookup_callback)(void *opaque, const struct flow_key *flow,
                                          const uint8_t lookup_key[64], uint64_t observed_ns,
                                          uint64_t socket_cookie);

int tcpra_pcap_build_filter(char *output, size_t output_size, const char *server_ip,
                            uint16_t server_port);

struct tcpra_pcap_observer *tcpra_pcap_observer_open(const char *server_ip, uint16_t server_port,
                                                     tcpra_pcap_lookup_callback lookup_callback,
                                                     tcpra_pcap_key_callback key_callback,
                                                     void *opaque);

int tcpra_pcap_observer_attach_ebpf(struct tcpra_pcap_observer *observer, int program_fd);

int tcpra_pcap_observer_poll(struct tcpra_pcap_observer *observer, int timeout_ms);

void tcpra_pcap_observer_counters(struct tcpra_pcap_observer *observer,
                                  unsigned long long *copied_packets,
                                  unsigned long long *copied_bytes,
                                  unsigned long long *received_by_filter,
                                  unsigned long long *dropped_by_kernel,
                                  unsigned long long *ch_split, unsigned long long *ch_reassembled);

void tcpra_pcap_observer_close(struct tcpra_pcap_observer *observer);

#endif
