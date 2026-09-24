#ifndef TCPRA_FLOW_GATE_H
#define TCPRA_FLOW_GATE_H

#ifdef __VMLINUX_H__
typedef __u8 tcpra_u8;
typedef __u16 tcpra_u16;
typedef __u32 tcpra_u32;
typedef __u64 tcpra_u64;
#else
#include <stdint.h>
typedef uint8_t tcpra_u8;
typedef uint16_t tcpra_u16;
typedef uint32_t tcpra_u32;
typedef uint64_t tcpra_u64;
#endif

struct flow_key {
    tcpra_u32 client_ip;
    tcpra_u32 server_ip;
    tcpra_u16 client_port;
    tcpra_u16 server_port;
};

struct flow_value {
    tcpra_u64 created_ns;
    tcpra_u64 last_seen_ns;
};

struct flow_config {
    tcpra_u32 server_ip;
    tcpra_u16 server_port;
    tcpra_u16 enabled;
};

struct flow_event {
    tcpra_u64 timestamp_ns;
    struct flow_key key;
    tcpra_u32 pid;
    tcpra_u32 old_state;
    tcpra_u32 new_state;
    tcpra_u8 action;
    tcpra_u8 reserved[7];
};

enum {
    FLOW_ADD = 1,
    FLOW_DELETE = 2,
};

#endif
