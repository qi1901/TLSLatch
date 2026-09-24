#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <libnftnl/set.h>

#include "flow_selector.h"

struct tcpra_flow_selector {
    struct mnl_socket *socket;
    uint32_t port_id;
    uint32_t sequence;
    uint32_t server_ip;
    uint16_t server_port;
    char table[64];
    char set[64];
};

struct nft_flow_key {
    uint32_t client_ip;
    uint16_t client_port;
    uint16_t client_padding;
    uint32_t server_ip;
    uint16_t server_port;
    uint16_t server_padding;
} __attribute__((packed));

_Static_assert(sizeof(struct nft_flow_key) == 16, "nftables concatenation key must be 16 bytes");

static int valid_identifier(const char *text) {
    if (!text || !*text || strlen(text) >= 64)
        return 0;
    for (const unsigned char *cursor = (const unsigned char *)text; *cursor; cursor++) {
        if (!isalnum(*cursor) && *cursor != '_')
            return 0;
    }
    return 1;
}

static int receive_ack(struct tcpra_flow_selector *selector, char *buffer, size_t buffer_size,
                       uint32_t sequence) {
    int length = mnl_socket_recvfrom(selector->socket, buffer, buffer_size);
    while (length > 0) {
        int result = mnl_cb_run(buffer, length, sequence, selector->port_id, NULL, NULL);
        if (result <= 0)
            return result == 0 ? 0 : -1;
        length = mnl_socket_recvfrom(selector->socket, buffer, buffer_size);
    }

    return -1;
}

static int delete_element(struct tcpra_flow_selector *selector, const struct flow_key *flow) {
    char buffer[MNL_SOCKET_BUFFER_SIZE];
    struct nftnl_set *set = nftnl_set_alloc();
    struct nftnl_set_elem *element = nftnl_set_elem_alloc();
    if (!set || !element) {
        nftnl_set_elem_free(element);
        nftnl_set_free(set);
        errno = ENOMEM;
        return -1;
    }

    struct nft_flow_key key = {
        .client_ip = flow->client_ip,
        .client_port = htons(flow->client_port),
        .server_ip = flow->server_ip,
        .server_port = htons(flow->server_port),
    };
    if (nftnl_set_set_str(set, NFTNL_SET_TABLE, selector->table) != 0 ||
        nftnl_set_set_str(set, NFTNL_SET_NAME, selector->set) != 0 ||
        nftnl_set_elem_set(element, NFTNL_SET_ELEM_KEY, &key, sizeof(key)) != 0) {
        nftnl_set_elem_free(element);
        nftnl_set_free(set);
        errno = EINVAL;
        return -1;
    }
    nftnl_set_elem_add(set, element);

    struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buffer, sizeof(buffer));
    if (!batch) {
        nftnl_set_free(set);
        errno = ENOMEM;
        return -1;
    }
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), selector->sequence++);
    mnl_nlmsg_batch_next(batch);
    struct nlmsghdr *header =
        nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch), NFT_MSG_DELSETELEM, NFPROTO_INET,
                                  NLM_F_ACK, selector->sequence++);
    uint32_t ack_sequence = header->nlmsg_seq;
    nftnl_set_elems_nlmsg_build_payload(header, set);
    nftnl_set_free(set);
    mnl_nlmsg_batch_next(batch);
    nftnl_batch_end(mnl_nlmsg_batch_current(batch), selector->sequence++);
    mnl_nlmsg_batch_next(batch);

    int result = mnl_socket_sendto(selector->socket, mnl_nlmsg_batch_head(batch),
                                   mnl_nlmsg_batch_size(batch));
    mnl_nlmsg_batch_stop(batch);
    if (result < 0)
        return -1;
    return receive_ack(selector, buffer, sizeof(buffer), ack_sequence);
}

struct tcpra_flow_selector *tcpra_flow_selector_open(const char *object_path, const char *server_ip,
                                                     uint16_t server_port,
                                                     const char *pin_directory) {
    if (!valid_identifier(object_path) || !valid_identifier(pin_directory) || !server_ip ||
        !server_port) {
        errno = EINVAL;
        return NULL;
    }
    struct tcpra_flow_selector *selector = calloc(1, sizeof(*selector));
    if (!selector)
        return NULL;
    selector->server_port = server_port;
    selector->sequence = 1;
    memcpy(selector->table, object_path, strlen(object_path) + 1);
    memcpy(selector->set, pin_directory, strlen(pin_directory) + 1);
    if (inet_pton(AF_INET, server_ip, &selector->server_ip) != 1)
        goto fail;
    selector->socket = mnl_socket_open(NETLINK_NETFILTER);
    if (!selector->socket || mnl_socket_bind(selector->socket, 0, MNL_SOCKET_AUTOPID) < 0)
        goto fail;
    selector->port_id = mnl_socket_get_portid(selector->socket);
    struct timeval timeout = {.tv_sec = 1, .tv_usec = 0};
    if (setsockopt(mnl_socket_get_fd(selector->socket), SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) != 0)
        goto fail;
    return selector;

fail:
    tcpra_flow_selector_close(selector);
    return NULL;
}

struct tcpra_flow_selector *tcpra_flow_selector_open_capture(const char *object_path,
                                                             const char *server_ip,
                                                             uint16_t server_port,
                                                             const char *pin_directory) {
    (void)object_path;
    (void)server_ip;
    (void)server_port;
    (void)pin_directory;
    errno = ENOTSUP;
    return NULL;
}

int tcpra_flow_selector_map_fd(const struct tcpra_flow_selector *selector) {
    (void)selector;
    return -1;
}

int tcpra_flow_selector_capture_program_fd(const struct tcpra_flow_selector *selector) {
    (void)selector;
    return -1;
}

int tcpra_flow_selector_delete(struct tcpra_flow_selector *selector, const struct flow_key *flow) {
    if (!selector || !flow || flow->server_ip != selector->server_ip ||
        flow->server_port != selector->server_port) {
        errno = EINVAL;
        return -1;
    }
    return delete_element(selector, flow);
}

void tcpra_flow_selector_close(struct tcpra_flow_selector *selector) {
    if (!selector)
        return;
    if (selector->socket)
        mnl_socket_close(selector->socket);
    free(selector);
}
