#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <pcap/pcap.h>

#include "packet_view.h"
#include "pcap_observer.h"
#include "tls_parse.h"
#include "wire_io.h"
#include "linux_safety.h"
#ifdef TCPRA_SERVER_SH_NFQUEUE
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#endif

#define TCPRA_PCAP_SNAPLEN 4096
#define TCPRA_PCAP_BUFFER_SIZE (1 << 20)
#define TCPRA_CH_STASH_SLOTS 128
#define TCPRA_CH_RECORD_MAX 2048
#define TCPRA_CH_STASH_TTL_NS (10ull * 1000000000ull)

struct tcpra_ch_stash {
    int used;
    int deferred;
    uint32_t raw_end;
    struct flow_key flow;
    uint32_t next_seq;
    size_t filled;
    size_t needed;
    uint64_t born_ns;
    uint8_t buf[TCPRA_CH_RECORD_MAX];
};

struct tcpra_pcap_observer {
    struct tcpra_pcap_observer *output;
    struct tcpra_pcap_observer *input;
    int is_output;
#ifdef TCPRA_SERVER_SH_NFQUEUE
    struct nfq_handle *nfq;
    struct nfq_q_handle *queue;
    int queue_fd;
    int queue_failed;
    unsigned long long sh_queued, sh_accepted, sh_rejected;
#endif
    pcap_t *handle;
    int fd;
    int datalink;
    uint16_t server_port;
    tcpra_pcap_lookup_callback lookup_callback;
    tcpra_pcap_key_callback key_callback;
    void *opaque;
    struct tcpra_ch_stash stashes[TCPRA_CH_STASH_SLOTS];
    unsigned long long copied_packets;
    unsigned long long copied_bytes;
    unsigned long long ch_split;
    unsigned long long ch_reassembled;
    unsigned long long ch_deferred, ch_recovered, ch_ack_mismatch;
    unsigned long long ch_stale;
};

int tcpra_pcap_build_filter(char *output, size_t output_size, const char *server_ip,
                            uint16_t server_port) {

    if (!output || output_size == 0 || !server_ip || server_port == 0)
        return 0;
    int written = snprintf(output, output_size,
                           "ip and tcp and ("
                           "(dst host %s and dst port %u and "
                           "tcp[((tcp[12] & 0xf0) >> 2)] = 0x16 and "
                           "tcp[((tcp[12] & 0xf0) >> 2) + 5] = 0x01) or "
                           "(dst host %s and dst port %u and ip[2:2] <= 376 and "
                           "ip[2:2] > ((ip[0] & 0x0f) << 2) + ((tcp[12] & 0xf0) >> 2)) or "
                           "(src host %s and src port %u and "
                           "tcp[((tcp[12] & 0xf0) >> 2)] = 0x16 and "
                           "tcp[((tcp[12] & 0xf0) >> 2) + 5] = 0x02))",
                           server_ip, server_port, server_ip, server_port, server_ip, server_port);
    return written > 0 && (size_t)written < output_size;
}

static char *find_capture_device(const char *server_ip, char error[PCAP_ERRBUF_SIZE]) {

    const char *configured = getenv("TCPRA_PCAP_DEVICE");

    struct in_addr wanted;
    pcap_if_t *devices = NULL;
    char *result = NULL;
    if (inet_pton(AF_INET, server_ip, &wanted) != 1) {
        snprintf(error, PCAP_ERRBUF_SIZE, "invalid server IPv4 address");
        return NULL;
    }
    if (pcap_findalldevs(&devices, error) != 0)
        return NULL;
    for (pcap_if_t *device = devices; device && !result; device = device->next) {
        if ((device->flags & PCAP_IF_LOOPBACK) ||
            (configured && *configured && strcmp(device->name, configured)))
            continue;
        for (pcap_addr_t *address = device->addresses; address; address = address->next) {
            if (!address->addr || address->addr->sa_family != AF_INET)
                continue;
            const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address->addr;
            if (ipv4->sin_addr.s_addr == wanted.s_addr) {
                result = strdup(device->name);
                break;
            }
        }
    }
    pcap_freealldevs(devices);
    if (!result)
        snprintf(error, PCAP_ERRBUF_SIZE, "no capture device owns the configured server address");
    return result;
}

static size_t network_offset(int datalink, const uint8_t *packet, size_t length) {
    if (!packet)
        return SIZE_MAX;
    if (datalink == DLT_RAW)
        return 0;
    if (datalink == DLT_LINUX_SLL)
        return length >= 16 ? 16u : SIZE_MAX;
#ifdef DLT_LINUX_SLL2
    if (datalink == DLT_LINUX_SLL2)
        return length >= 20 ? 20u : SIZE_MAX;
#endif
    if (datalink != DLT_EN10MB || length < 14)
        return SIZE_MAX;
    size_t offset = 14;
    uint16_t protocol = ((uint16_t)packet[12] << 8) | packet[13];
    for (int depth = 0; depth < 2 && (protocol == 0x8100 || protocol == 0x88a8); depth++) {
        if (offset + 4 > length)
            return SIZE_MAX;
        protocol = ((uint16_t)packet[offset + 2] << 8) | packet[offset + 3];
        offset += 4;
    }
    return protocol == 0x0800 ? offset : SIZE_MAX;
}

static int ch_same_flow(const struct flow_key *a, const struct flow_key *b) {
    return a->client_ip == b->client_ip && a->server_ip == b->server_ip &&
           a->client_port == b->client_port && a->server_port == b->server_port;
}

static int ch_emit(struct tcpra_pcap_observer *observer, const struct flow_key *flow,
                   const uint8_t *record, size_t length) {
    uint8_t lookup_key[RA_KEY_SIZE];
    if (!tcpra_tls_find_clienthello(record, length, lookup_key))
        return 0;
    uint64_t cookie;

    static int force_once = -1;
    if (force_once < 0)
        force_once = getenv("TCPRA_TEST_DEFER_CH_ONCE") != NULL;
    if (force_once) {
        force_once = 0;
        return -1;
    }
    if (!tcpra_socket_cookie(flow, 1, &cookie))
        return -1;
    observer->lookup_callback(observer->opaque, flow, lookup_key, tcpra_now_ns(), cookie);
    return 1;
}

static struct tcpra_ch_stash *ch_find_stash(struct tcpra_pcap_observer *observer,
                                            const struct flow_key *flow) {
    uint64_t now = tcpra_now_ns();
    for (size_t i = 0; i < TCPRA_CH_STASH_SLOTS; i++) {
        struct tcpra_ch_stash *slot = &observer->stashes[i];
        if (!slot->used)
            continue;
        if (now - slot->born_ns > TCPRA_CH_STASH_TTL_NS) {
            observer->ch_stale++;
            slot->used = 0;
            continue;
        }
        if (ch_same_flow(&slot->flow, flow))
            return slot;
    }
    return NULL;
}

static void ch_clear_stash(struct tcpra_pcap_observer *observer, const struct flow_key *flow) {
    struct tcpra_ch_stash *slot = ch_find_stash(observer, flow);
    if (slot)
        slot->used = 0;
}

static struct tcpra_ch_stash *ch_claim_stash(struct tcpra_pcap_observer *observer,
                                             const struct flow_key *flow) {
    struct tcpra_ch_stash *slot = ch_find_stash(observer, flow);
    if (slot) {
        observer->ch_stale++;
    } else {
        slot = &observer->stashes[0];
        for (size_t i = 0; i < TCPRA_CH_STASH_SLOTS; i++) {
            if (!observer->stashes[i].used) {
                slot = &observer->stashes[i];
                break;
            }
            if (observer->stashes[i].born_ns < slot->born_ns)
                slot = &observer->stashes[i];
        }
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = 1;
    slot->flow = *flow;
    slot->born_ns = tcpra_now_ns();
    return slot;
}

static void ch_feed(struct tcpra_pcap_observer *observer, const struct flow_key *flow,
                    const struct tcpra_ipv4_tcp_view *view) {
    if (view->payload_length >= 5 && view->payload[0] == 22) {
        size_t needed = 5 + (((size_t)view->payload[3] << 8) | view->payload[4]);
        if (needed <= view->payload_length) {

            uint8_t key[RA_KEY_SIZE];
            if (needed <= TCPRA_CH_RECORD_MAX &&
                tcpra_tls_find_clienthello(view->payload, needed, key)) {
                struct tcpra_ch_stash *slot = ch_claim_stash(observer, flow);
                memcpy(slot->buf, view->payload, needed);
                slot->filled = slot->needed = needed;
                slot->deferred = 1;
                slot->raw_end = view->raw_sequence + (uint32_t)view->payload_length;
                observer->ch_deferred++;
            } else
                ch_clear_stash(observer, flow);
            return;
        }
        if (needed > TCPRA_CH_RECORD_MAX) {
            ch_clear_stash(observer, flow);
            return;
        }
        struct tcpra_ch_stash *slot = ch_claim_stash(observer, flow);
        memcpy(slot->buf, view->payload, view->payload_length);
        slot->filled = view->payload_length;
        slot->needed = needed;
        slot->next_seq = view->sequence + (uint32_t)view->payload_length;
        observer->ch_split++;
        return;
    }
    struct tcpra_ch_stash *slot = ch_find_stash(observer, flow);
    if (!slot)
        return;
    if (view->sequence != slot->next_seq || slot->filled + view->payload_length > slot->needed)
        return;
    memcpy(slot->buf + slot->filled, view->payload, view->payload_length);
    slot->filled += view->payload_length;
    slot->next_seq += (uint32_t)view->payload_length;
    if (slot->filled == slot->needed) {
        int emitted = ch_emit(observer, flow, slot->buf, slot->filled);
        observer->ch_reassembled++;
        if (emitted < 0) {
            slot->deferred = 1;
            slot->raw_end = view->raw_sequence + (uint32_t)view->payload_length;
            observer->ch_deferred++;
        } else
            slot->used = 0;
    }
}

static void capture_packet(unsigned char *opaque, const struct pcap_pkthdr *header,
                           const unsigned char *packet) {
    struct tcpra_pcap_observer *observer = (struct tcpra_pcap_observer *)opaque;
    if (!observer || !header || !packet)
        return;
    observer->copied_packets++;
    observer->copied_bytes += header->caplen;

    size_t offset = network_offset(observer->datalink, packet, header->caplen);
    if (offset == SIZE_MAX || offset >= header->caplen)
        return;
    struct tcpra_ipv4_tcp_view view;
    if (!tcpra_parse_ipv4_tcp(packet + offset, header->caplen - offset, &view) ||
        view.payload_length == 0)
        return;

    struct flow_key flow;
    int client_to_server = 0;
    if (!tcpra_normalize_flow(&view, observer->server_port, &flow, &client_to_server))
        return;

    if (client_to_server == observer->is_output)
        return;
    if (client_to_server) {
        if (view.payload_length > 5 && view.payload[0] == 22 &&
            ch_emit(observer, &flow, view.payload, view.payload_length) > 0) {
            ch_clear_stash(observer, &flow);
            return;
        }
        ch_feed(observer, &flow, &view);
        return;
    }

    if (view.payload_length <= 5 || view.payload[0] != 22)
        return;
    uint16_t group_id = 0;
    uint8_t public_key[TCPRA_MAX_PUBLIC_KEY];
    size_t public_key_length = 0;
    uint8_t report_key[RA_KEY_SIZE];
    if (!tcpra_tls_find_serverhello(view.payload, view.payload_length, &group_id, public_key,
                                    &public_key_length, report_key))
        return;
    (void)report_key;
    uint64_t cookie;
    if (!tcpra_socket_cookie(&flow, 1, &cookie))
        return;

    if (observer->input) {
        struct tcpra_pcap_observer *input = observer->input;
        struct tcpra_ch_stash *slot = ch_find_stash(input, &flow);
        if (slot && slot->deferred) {
            uint64_t fresh;
            if (slot->raw_end == view.acknowledgement && tcpra_socket_cookie(&flow, 1, &fresh) &&
                fresh == cookie) {
                uint8_t key[RA_KEY_SIZE];
                if (tcpra_tls_find_clienthello(slot->buf, slot->filled, key) &&
                    input->lookup_callback(input->opaque, &flow, key, slot->born_ns, cookie))
                    input->ch_recovered++;
                slot->used = 0;
            } else {
                input->ch_ack_mismatch++;
                slot->used = 0;
            }
        }
    }
    observer->key_callback(observer->opaque, &flow, group_id, public_key, public_key_length,
                           tcpra_now_ns(), cookie);
}

#ifdef TCPRA_SERVER_SH_NFQUEUE

static int sh_queue_callback(struct nfq_q_handle *queue, struct nfgenmsg *msg,
                             struct nfq_data *data, void *opaque) {
    (void)msg;
    struct tcpra_pcap_observer *observer = opaque;
    struct nfqnl_msg_packet_hdr *header = nfq_get_msg_packet_hdr(data);
    if (!header) {
        observer->queue_failed = 1;
        return -1;
    }
    uint32_t id = ntohl(header->packet_id);
    unsigned char *packet = NULL;
    int length = nfq_get_payload(data, &packet);
    uint32_t verdict = NF_DROP;
    observer->copied_packets++;
    if (length > 0)
        observer->copied_bytes += (unsigned)length;
    struct tcpra_ipv4_tcp_view view;
    struct flow_key flow;
    int c2s;
    uint16_t group;
    uint8_t pub[TCPRA_MAX_PUBLIC_KEY], key[RA_KEY_SIZE];
    size_t pub_length;
    uint64_t cookie;
    if (length <= 0 || !tcpra_parse_ipv4_tcp(packet, (size_t)length, &view) ||
        !tcpra_normalize_flow(&view, observer->server_port, &flow, &c2s) || c2s ||
        nfq_get_indev(data) != 0 || nfq_get_outdev(data) == 0)
        goto done;

    if (!tcpra_tls_find_serverhello(view.payload, view.payload_length, &group, pub, &pub_length,
                                    key)) {
        fprintf(stderr, "SERVER_SH_CANDIDATE_IGNORED packet=%u bytes=%d\n", id, length);
        return nfq_set_verdict(queue, id, NF_ACCEPT, 0, NULL);
    }
    observer->sh_queued++;
    if (!tcpra_socket_cookie(&flow, 1, &cookie))
        goto done;
    if (pcap_dispatch(observer->handle, -1, capture_packet, (unsigned char *)observer) < 0)
        goto done;
    if (!observer->key_callback(observer->opaque, &flow, group, pub, pub_length, tcpra_now_ns(),
                                cookie))
        goto done;
    verdict = NF_ACCEPT;
done:
    if (verdict == NF_ACCEPT)
        observer->sh_accepted++;
    else {
        observer->sh_rejected++;
        observer->queue_failed = 1;
        fprintf(stderr, "SERVER_SH_OBSERVATION_FAILED packet=%u\n", id);
        fflush(stderr);
    }
    if (nfq_set_verdict2(queue, id, verdict, verdict == NF_ACCEPT ? 0x544c0002u : 0, 0, NULL) < 0) {
        observer->queue_failed = 1;
        return -1;
    }
    return 0;
}

static int open_sh_queue(struct tcpra_pcap_observer *observer) {
    const char *value = getenv("TCPRA_SERVER_SH_QUEUE");
    char *end;
    if (!value || !*value)
        return 0;
    unsigned long number = strtoul(value, &end, 10);
    if (*end || number > 65535)
        return 0;
    observer->nfq = nfq_open();
    if (!observer->nfq || nfq_bind_pf(observer->nfq, AF_INET) < 0)
        return 0;
    observer->queue =
        nfq_create_queue(observer->nfq, (uint16_t)number, sh_queue_callback, observer);
    if (!observer->queue ||
        nfq_set_mode(observer->queue, NFQNL_COPY_PACKET, TCPRA_PCAP_SNAPLEN) < 0 ||
        nfq_set_queue_maxlen(observer->queue, 1024) < 0)
        return 0;
    observer->queue_fd = nfq_fd(observer->nfq);
    int size = 1 << 20;
    if (setsockopt(observer->queue_fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)))
        return 0;
    fprintf(stderr, "SERVER_SH_QUEUE_READY queue=%lu\n", number);
    return 1;
}
#endif

static struct tcpra_pcap_observer *open_lane(const char *server_ip, uint16_t server_port,
                                             tcpra_pcap_lookup_callback lookup_callback,
                                             tcpra_pcap_key_callback key_callback, void *opaque,
                                             int output) {
    if (!server_ip || !server_port || !lookup_callback || !key_callback)
        return NULL;
    struct tcpra_pcap_observer *observer = calloc(1, sizeof(*observer));
    if (!observer)
        return NULL;
    observer->fd = -1;
    observer->is_output = output;
    observer->server_port = server_port;
    observer->lookup_callback = lookup_callback;
    observer->key_callback = key_callback;
    observer->opaque = opaque;

    char error[PCAP_ERRBUF_SIZE] = {0};
    char *device = find_capture_device(server_ip, error);
    if (!device)
        goto fail;
    observer->handle = pcap_create(device, error);
    free(device);
    if (!observer->handle || pcap_set_snaplen(observer->handle, TCPRA_PCAP_SNAPLEN) != 0 ||
        pcap_set_promisc(observer->handle, 0) != 0 || pcap_set_timeout(observer->handle, 1) != 0 ||
        pcap_set_immediate_mode(observer->handle, 1) != 0 ||
        pcap_set_buffer_size(observer->handle, TCPRA_PCAP_BUFFER_SIZE) != 0 ||
        pcap_activate(observer->handle) < 0)
        goto fail;
    observer->datalink = pcap_datalink(observer->handle);

    if (observer->datalink != DLT_EN10MB ||
        pcap_setdirection(observer->handle, output ? PCAP_D_OUT : PCAP_D_IN))
        goto fail;
    char filter[512];
    struct bpf_program program;
    memset(&program, 0, sizeof(program));
    if (!tcpra_pcap_build_filter(filter, sizeof(filter), server_ip, server_port) ||
        pcap_compile(observer->handle, &program, filter, 1, PCAP_NETMASK_UNKNOWN) != 0)
        goto fail;
    int filter_ok = pcap_setfilter(observer->handle, &program) == 0;
    pcap_freecode(&program);
    if (!filter_ok || pcap_setnonblock(observer->handle, 1, error) != 0)
        goto fail;
    observer->fd = pcap_get_selectable_fd(observer->handle);
    if (observer->fd < 0)
        goto fail;
    return observer;

fail:
    if (error[0])
        fprintf(stderr, "pcap observer initialization failed: %s\n", error);
    else if (observer->handle)
        fprintf(stderr, "pcap observer initialization failed: %s\n", pcap_geterr(observer->handle));
    tcpra_pcap_observer_close(observer);
    return NULL;
}

struct tcpra_pcap_observer *tcpra_pcap_observer_open(const char *server_ip, uint16_t server_port,
                                                     tcpra_pcap_lookup_callback lookup_callback,
                                                     tcpra_pcap_key_callback key_callback,
                                                     void *opaque) {
    if (!tcpra_origin_guard(server_ip, server_port))
        return NULL;
    struct tcpra_pcap_observer *observer =
        open_lane(server_ip, server_port, lookup_callback, key_callback, opaque, 0);
    if (!observer)
        return NULL;
#ifdef TCPRA_SERVER_SH_NFQUEUE
    if (!open_sh_queue(observer)) {
        tcpra_pcap_observer_close(observer);
        return NULL;
    }
#else
    observer->output = open_lane(server_ip, server_port, lookup_callback, key_callback, opaque, 1);
    if (!observer->output) {
        tcpra_pcap_observer_close(observer);
        return NULL;
    }
    observer->output->input = observer;
#endif
    return observer;
}

int tcpra_pcap_observer_attach_ebpf(struct tcpra_pcap_observer *observer, int program_fd) {
    (void)observer;
    (void)program_fd;
    errno = ENOTSUP;
    return 0;
}

int tcpra_pcap_observer_poll(struct tcpra_pcap_observer *observer, int timeout_ms) {
    if (!observer || !observer->handle || observer->fd < 0)
        return -EINVAL;
#ifdef TCPRA_SERVER_SH_NFQUEUE
    struct pollfd descriptors[2] = {{.fd = observer->fd, .events = POLLIN},
                                    {.fd = observer->queue_fd, .events = POLLIN}};
    int ready = poll(descriptors, 2, timeout_ms);
    if (ready < 0)
        return -errno;
    for (int i = 0; i < 2; i++)
        if (descriptors[i].revents & (POLLERR | POLLHUP | POLLNVAL))
            return -EIO;
    if (descriptors[0].revents & POLLIN)
        if (pcap_dispatch(observer->handle, -1, capture_packet, (unsigned char *)observer) < 0)
            return -EIO;
    if (descriptors[1].revents & POLLIN) {
        unsigned char buffer[65536] __attribute__((aligned));
        int n = (int)recv(observer->queue_fd, buffer, sizeof(buffer), 0);
        if (n < 0)
            return -errno;
        if (nfq_handle_packet(observer->nfq, (char *)buffer, n) < 0)
            return -EIO;
    }
    return observer->queue_failed ? -EIO : ready;
#else
    struct pollfd descriptors[2] = {{.fd = observer->fd, .events = POLLIN},
                                    {.fd = observer->output->fd, .events = POLLIN}};
    int ready = poll(descriptors, 2, timeout_ms);
    if (ready < 0)
        return -errno;
    int total = 0;
    for (int i = 0; i < 2; i++) {
        struct tcpra_pcap_observer *lane = i ? observer->output : observer;
        if (descriptors[i].revents & (POLLERR | POLLHUP | POLLNVAL))
            return -EIO;
        if (!(descriptors[i].revents & POLLIN))
            continue;
        int n = pcap_dispatch(lane->handle, -1, capture_packet, (unsigned char *)lane);
        if (n < 0)
            return -EIO;
        total += n;
    }
    return total;
#endif
}

void tcpra_pcap_observer_counters(struct tcpra_pcap_observer *observer,
                                  unsigned long long *copied_packets,
                                  unsigned long long *copied_bytes,
                                  unsigned long long *received_by_filter,
                                  unsigned long long *dropped_by_kernel,
                                  unsigned long long *ch_split,
                                  unsigned long long *ch_reassembled) {
    if (observer)
        fprintf(stderr, "CH_DEFER_SUMMARY deferred=%llu recovered=%llu ack_mismatch=%llu\n",
                observer->ch_deferred, observer->ch_recovered, observer->ch_ack_mismatch);
    if (copied_packets)
        *copied_packets = observer ? observer->copied_packets : 0;
    if (copied_bytes)
        *copied_bytes = observer ? observer->copied_bytes : 0;
    if (ch_split)
        *ch_split = observer ? observer->ch_split : 0;
    if (ch_reassembled)
        *ch_reassembled = observer ? observer->ch_reassembled : 0;
    struct pcap_stat statistics = {0};
    int have_stats = observer && observer->handle && pcap_stats(observer->handle, &statistics) == 0;
    if (received_by_filter)
        *received_by_filter = have_stats ? statistics.ps_recv : 0;
    if (dropped_by_kernel)
        *dropped_by_kernel = have_stats ? statistics.ps_drop : 0;
    if (observer && observer->output) {
        unsigned long long p, b, r, d, s, a;
        tcpra_pcap_observer_counters(observer->output, &p, &b, &r, &d, &s, &a);
        if (copied_packets)
            *copied_packets += p;
        if (copied_bytes)
            *copied_bytes += b;
        if (received_by_filter)
            *received_by_filter += r;
        if (dropped_by_kernel)
            *dropped_by_kernel += d;
        if (ch_split)
            *ch_split += s;
        if (ch_reassembled)
            *ch_reassembled += a;
    }
}

void tcpra_pcap_observer_close(struct tcpra_pcap_observer *observer) {
    if (!observer)
        return;
#ifdef TCPRA_SERVER_SH_NFQUEUE
    fprintf(stderr, "SERVER_SH_QUEUE_SUMMARY queued=%llu accepted=%llu rejected=%llu failed=%d\n",
            observer->sh_queued, observer->sh_accepted, observer->sh_rejected,
            observer->queue_failed);
    if (observer->queue)
        nfq_destroy_queue(observer->queue);
    if (observer->nfq)
        nfq_close(observer->nfq);
#endif
    if (observer->handle)
        pcap_close(observer->handle);
    tcpra_pcap_observer_close(observer->output);
    free(observer);
}
