#ifndef TCPRA_LINUX_SAFETY_H
#define TCPRA_LINUX_SAFETY_H
#include <arpa/inet.h>
#include <errno.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include "flow_gate.h"

static inline int tcpra_socket_cookie_state(const struct flow_key *flow, int server_role,
                                            unsigned state, uint64_t *cookie) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0)
        return 0;
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 100000};
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    struct {
        struct nlmsghdr h;
        struct inet_diag_req_v2 r;
    } request = {0};
    request.h.nlmsg_len = sizeof(request);
    request.h.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    request.h.nlmsg_flags = NLM_F_REQUEST;
    request.h.nlmsg_seq = 1;
    request.r.sdiag_family = AF_INET;
    request.r.sdiag_protocol = IPPROTO_TCP;
    request.r.idiag_states = 1u << state;
    request.r.id.idiag_src[0] = server_role ? flow->server_ip : flow->client_ip;
    request.r.id.idiag_dst[0] = server_role ? flow->client_ip : flow->server_ip;
    request.r.id.idiag_sport = htons(server_role ? flow->server_port : flow->client_port);
    request.r.id.idiag_dport = htons(server_role ? flow->client_port : flow->server_port);
    request.r.id.idiag_cookie[0] = request.r.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    int ok = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
        sendto(fd, &request, sizeof(request), 0, (void *)&kernel, sizeof(kernel)) !=
            sizeof(request))
        goto done;
    union {
        struct nlmsghdr align;
        unsigned char bytes[4096];
    } buffer;
    struct sockaddr_nl sender = {0};
    socklen_t sender_size = sizeof(sender);
    int count =
        (int)recvfrom(fd, buffer.bytes, sizeof(buffer.bytes), 0, (void *)&sender, &sender_size);
    if (sender.nl_pid != 0)
        goto done;
    for (struct nlmsghdr *h = (void *)buffer.bytes; NLMSG_OK(h, count); h = NLMSG_NEXT(h, count)) {
        if (h->nlmsg_seq != 1 || h->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
            h->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg)))
            continue;
        struct inet_diag_msg *m = NLMSG_DATA(h);
        if (m->idiag_family != AF_INET || m->idiag_state != state ||
            m->id.idiag_src[0] != request.r.id.idiag_src[0] ||
            m->id.idiag_dst[0] != request.r.id.idiag_dst[0] ||
            m->id.idiag_sport != request.r.id.idiag_sport ||
            m->id.idiag_dport != request.r.id.idiag_dport)
            continue;
        *cookie = ((uint64_t)m->id.idiag_cookie[1] << 32) | m->id.idiag_cookie[0];
        ok = *cookie != UINT64_MAX;
        break;
    }
done:
    close(fd);
    return ok;
}

static inline int tcpra_socket_cookie(const struct flow_key *flow, int server_role,
                                      uint64_t *cookie) {
    return tcpra_socket_cookie_state(flow, server_role, 1, cookie);
}

static inline int tcpra_nft_transaction(const char *rules) {
    int p[2];
    if (pipe(p))
        return 0;
    pid_t pid = fork();
    if (pid == 0) {
        dup2(p[0], STDIN_FILENO);
        close(p[0]);
        close(p[1]);
        execlp("nft", "nft", "-f", "-", (char *)NULL);
        _exit(127);
    }
    close(p[0]);
    if (pid < 0) {
        close(p[1]);
        return 0;
    }
    size_t length = strlen(rules), sent = 0;
    while (sent < length) {
        ssize_t n = write(p[1], rules + sent, length - sent);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        sent += (size_t)n;
    }
    close(p[1]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return 0;
    }
    return sent == length && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static inline int tcpra_origin_guard(const char *ip, uint16_t port) {
    struct in_addr address;
    if (inet_pton(AF_INET, ip, &address) != 1 || !port)
        return 0;
    char rules[1024];

    snprintf(rules, sizeof(rules),
             "add table inet tlslatch_origin_%u\n"
             "add chain inet tlslatch_origin_%u forward { type filter hook forward priority -320; "
             "policy accept; }\n"
             "flush chain inet tlslatch_origin_%u forward\n"
             "add rule inet tlslatch_origin_%u forward ip saddr %s tcp sport %u drop\n"
             "add rule inet tlslatch_origin_%u forward ip daddr %s tcp dport %u drop\n",
             port, port, port, port, ip, port, port, ip, port);
    return tcpra_nft_transaction(rules);
}

static inline int tcpra_quarantine(const char *ip, uint16_t port) {
    struct in_addr address;
    if (inet_pton(AF_INET, ip, &address) != 1 || !port)
        return 0;
    char rules[1500];
    snprintf(
        rules, sizeof(rules),
        "add table inet tlslatch_quarantine\n"
        "add set inet tlslatch_quarantine blocked4 { type ipv4_addr . inet_service; }\n"
        "add chain inet tlslatch_quarantine quarantine_output { type filter hook output priority "
        "-320; policy accept; }\n"
        "add chain inet tlslatch_quarantine quarantine_input { type filter hook input priority "
        "-320; policy accept; }\n"
        "add rule inet tlslatch_quarantine quarantine_output ip daddr . tcp dport @blocked4 drop\n"
        "add rule inet tlslatch_quarantine quarantine_input ip saddr . tcp sport @blocked4 drop\n"
        "add element inet tlslatch_quarantine blocked4 { %s . %u }\n",
        ip, port);
    return tcpra_nft_transaction(rules);
}
#endif
