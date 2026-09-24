#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "wire_io.h"

uint64_t tcpra_now_ns(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000000000ull + (uint64_t)now.tv_nsec;
}

uint64_t tcpra_network_u64(uint64_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl((uint32_t)value) << 32) | htonl((uint32_t)(value >> 32));
#else
    return value;
#endif
}

int tcpra_read_all(int fd, void *buffer, size_t length) {
    uint8_t *position = buffer;
    while (length) {
        ssize_t received = recv(fd, position, length, MSG_WAITALL);
        if (received < 0 && errno == EINTR)
            continue;
        if (received <= 0)
            return 0;
        position += received;
        length -= (size_t)received;
    }
    return 1;
}

int tcpra_write_all(int fd, const void *buffer, size_t length) {
    const uint8_t *position = buffer;
    while (length) {
        ssize_t sent = send(fd, position, length, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR)
            continue;
        if (sent <= 0)
            return 0;
        position += sent;
        length -= (size_t)sent;
    }
    return 1;
}

int tcpra_write_pair(int fd, const void *first, size_t first_length, const void *second,
                     size_t second_length) {
    struct iovec vectors[2] = {
        {.iov_base = (void *)first, .iov_len = first_length},
        {.iov_base = (void *)second, .iov_len = second_length},
    };
    size_t index = 0;
    while (index < 2) {
        struct msghdr message = {
            .msg_iov = vectors + index,
            .msg_iovlen = 2 - index,
        };
        ssize_t sent = sendmsg(fd, &message, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR)
            continue;
        if (sent <= 0)
            return 0;
        size_t consumed = (size_t)sent;
        while (index < 2 && consumed >= vectors[index].iov_len) {
            consumed -= vectors[index].iov_len;
            index++;
        }
        if (index < 2 && consumed) {
            vectors[index].iov_base = (uint8_t *)vectors[index].iov_base + consumed;
            vectors[index].iov_len -= consumed;
        }
    }
    return 1;
}

int tcpra_listen_tcp(uint16_t port, int backlog) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int enabled = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(fd, backlog) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}
