#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/egress_key.h>
#include <common/fd_info.h>
#include <common/protocol_defs.h>

#include <logger/bpf_dbg.h>

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

typedef struct connection_info_part {
    union {
        u8 addr[IP_V6_ADDR_LEN];
        u32 ip[IP_V6_ADDR_LEN_WORDS];
    };
    u32 pid;
    u16 port;
    u8 type;
    u8 __pad;
} connection_info_part_t;

#ifdef BPF_DEBUG
static __always_inline void dbg_print_http_connection_info(connection_info_t *info) {
    bpf_dbg_printk("[conn] s_h = %llx, s_l = %llx, s_port=%d",
                   *(u64 *)(&info->s_addr),
                   *(u64 *)(&info->s_addr[8]),
                   info->s_port);
    bpf_dbg_printk("[conn] d_h = %llx, d_l = %llx, d_port=%d",
                   *(u64 *)(&info->d_addr),
                   *(u64 *)(&info->d_addr[8]),
                   info->d_port);
}
static __always_inline void dbg_print_http_connection_info_part(connection_info_part_t *info) {
    bpf_dbg_printk("[conn part] s_h = %llx, s_l = %llx, s_port=%d",
                   *(u64 *)(&info->addr),
                   *(u64 *)(&info->addr[8]),
                   info->port);
}
static __always_inline void d_print_http_connection_info(connection_info_t *info) {
    bpf_d_printk("[conn] s_h = %llx, s_l = %llx, s_port=%d",
                 *(u64 *)(&info->s_addr),
                 *(u64 *)(&info->s_addr[8]),
                 info->s_port);
    bpf_d_printk("[conn] d_h = %llx, d_l = %llx, d_port=%d",
                 *(u64 *)(&info->d_addr),
                 *(u64 *)(&info->d_addr[8]),
                 info->d_port);
}
#else
static __always_inline void dbg_print_http_connection_info(connection_info_t *info) {
}
static __always_inline void dbg_print_http_connection_info_part(connection_info_part_t *info) {
}
static __always_inline void d_print_http_connection_info(connection_info_t *info) {
}
#endif

const u8 ip4ip6_prefix[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

static __always_inline bool likely_ephemeral_port(u16 port) {
    return port >= EPHEMERAL_PORT_MIN;
}

#define __SWAP(T, x, y)                                                                            \
    {                                                                                              \
        T TMP = x;                                                                                 \
        x = y;                                                                                     \
        y = TMP;                                                                                   \
    }

static __always_inline void swap_connection_info_order(connection_info_t *info) {
    __SWAP(u16, info->s_port, info->d_port);
    u8 tmp_addr[IP_V6_ADDR_LEN];
    __builtin_memcpy(tmp_addr, info->s_addr, sizeof(tmp_addr));
    __builtin_memcpy(info->s_addr, info->d_addr, sizeof(info->s_addr));
    __builtin_memcpy(info->d_addr, tmp_addr, sizeof(info->d_addr));
}

// Since we track both send and receive connections, we need to sort the source and destination
// pairs in a standardized way, we choose the server way of sorting, such that the ephemeral port
// on the client is first.
static __always_inline void sort_connection_info(connection_info_t *info) {
    if (likely_ephemeral_port(info->s_port) && !likely_ephemeral_port(info->d_port)) {
        return;
    }

    if ((likely_ephemeral_port(info->d_port) && !likely_ephemeral_port(info->s_port)) ||
        (info->d_port > info->s_port)) {
        // Only sort if they are explicitly reversed, otherwise always sort source to be the larger
        // of the two ports
        swap_connection_info_order(info);
    }
}

// Equivalent to sort_connection_info, but works only with the ports key (egress_key_t),
// which we use for egress connection tracking
static __always_inline void sort_egress_key(egress_key_t *info) {
    if (likely_ephemeral_port(info->s_port) && !likely_ephemeral_port(info->d_port)) {
        return;
    }

    if ((likely_ephemeral_port(info->d_port) && !likely_ephemeral_port(info->s_port)) ||
        (info->d_port > info->s_port)) {
        __SWAP(u16, info->s_port, info->d_port);
    }
}

static __always_inline bool client_call(connection_info_t *info) {
    return likely_ephemeral_port(info->s_port) && !likely_ephemeral_port(info->d_port);
}

// We sort the connection info to ensure we can track requests and responses. However, if the destination port
// is somehow in the ephemeral port range, it can be higher than the source port and we'd use the sorted connection
// info in user space, effectively reversing the flow of the operation. We keep track of the original destination port
// and we undo the swap in the data collections we send to user space.
static __always_inline void
fixup_connection_info(connection_info_t *conn_info, u8 client, u16 orig_dport) {
    if (!orig_dport) {
        bpf_dbg_printk("orig_dport is 0, not swapping");
        return;
    }
    // The destination port is the server port in userspace
    if ((client && conn_info->d_port != orig_dport) ||
        (!client && conn_info->d_port == orig_dport)) {
        bpf_dbg_printk("Swapped connection info for userspace, client = %d, orig_dport = %d",
                       client,
                       orig_dport);
        swap_connection_info_order(conn_info);
        //dbg_print_http_connection_info(conn_info); // commented out since GitHub CI doesn't like this call
    }
}

static __always_inline void
populate_partial_info(connection_info_part_t *part, const u8 *addr, u16 port) {
    __builtin_memcpy(part->addr, addr, IP_V6_ADDR_LEN);
    part->port = port;
}

static __always_inline void populate_ephemeral_info(connection_info_part_t *part,
                                                    const connection_info_t *sorted_conn,
                                                    u16 orig_dport,
                                                    u32 pid,
                                                    u8 type) {

    if ((type == FD_CLIENT && sorted_conn->d_port != orig_dport) ||
        (type == FD_SERVER && sorted_conn->d_port == orig_dport)) {
        populate_partial_info(part, sorted_conn->d_addr, sorted_conn->d_port);
    } else {
        populate_partial_info(part, sorted_conn->s_addr, sorted_conn->s_port);
    }

    part->type = type;
    part->pid = pid;
}
