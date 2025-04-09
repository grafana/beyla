#pragma once

#include <bpfcore/vmlinux.h>

#include <common/protocol_defs.h>

// Struct to keep information on the connections in flight
// s = source, d = destination
// h = high word, l = low word
// used as hashmap key, must be 4 byte aligned?
typedef struct connection_info {
    union {
        u8 s_addr[IP_V6_ADDR_LEN];
        u32 s_ip[IP_V6_ADDR_LEN_WORDS];
    };
    union {
        u8 d_addr[IP_V6_ADDR_LEN];
        u32 d_ip[IP_V6_ADDR_LEN_WORDS];
    };
    u16 s_port;
    u16 d_port;
} connection_info_t;

typedef struct http_partial_connection_info {
    u8 s_addr[IP_V6_ADDR_LEN];
    u16 s_port;
    u16 d_port;
    u32 tcp_seq;
} partial_connection_info_t;

typedef struct http_pid_connection_info {
    connection_info_t conn;
    u32 pid;
} pid_connection_info_t;

typedef struct ssl_pid_connection_info {
    pid_connection_info_t p_conn;
    u16 orig_dport;
    u8 _pad[6];
} ssl_pid_connection_info_t;
