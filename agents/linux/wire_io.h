#ifndef TCPRA_UNIFIED_WIRE_IO_H
#define TCPRA_UNIFIED_WIRE_IO_H

#include <stddef.h>
#include <stdint.h>

uint64_t tcpra_now_ns(void);
uint64_t tcpra_network_u64(uint64_t value);
int tcpra_read_all(int fd, void *buffer, size_t length);
int tcpra_write_all(int fd, const void *buffer, size_t length);
int tcpra_write_pair(int fd, const void *first, size_t first_length, const void *second,
                     size_t second_length);
int tcpra_listen_tcp(uint16_t port, int backlog);

#endif
