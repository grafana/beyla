#ifndef SOCKADDR_HELPERS_H
#define SOCKADDR_HELPERS_H

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"
#include "http_types.h"
#include "http_defs.h"

typedef struct accept_args {
    u64 addr; // linux sock or socket address
    u64 accept_time;
} accept_args_t;

static __always_inline bool ipv4_mapped_ipv6(u64 addr_h, u64 addr_l) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return (addr_h == 0 && ((u32)addr_l == 0xFFFF0000));
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return (addr_h == 0 && ((u32)(addr_l >> 32) == 0x0000FFFF));
#else
    return false
#endif
}

static __always_inline void parse_sock_info(accept_args_t *args, http_connection_info_t *info) {
    struct sock* s;

    struct socket *sock = (struct socket*)(args->addr);
    BPF_CORE_READ_INTO(&s, sock, sk);

    short unsigned int skc_family;
    BPF_CORE_READ_INTO(&skc_family, s, __sk_common.skc_family);
    
    if (skc_family == AF_INET) {
        BPF_CORE_READ_INTO(&info->s_port, s, __sk_common.skc_num);
        BPF_CORE_READ_INTO(&info->s_l, s, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&info->d_port, s, __sk_common.skc_dport);
        info->d_port = bpf_ntohs(info->d_port);
        BPF_CORE_READ_INTO(&info->d_l, s, __sk_common.skc_daddr);
        info->flags |= F_HTTP_IP4;

        info->s_h = 0;
        info->d_h = 0;
    } else if (skc_family == AF_INET6) {
        u8 d_addr_v6[IP_V6_ADDR_LEN];
        u8 s_addr_v6[IP_V6_ADDR_LEN];


        BPF_CORE_READ_INTO(&info->s_port, s, __sk_common.skc_num);
        BPF_CORE_READ_INTO(&s_addr_v6, s, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&info->d_port, s, __sk_common.skc_dport);
        info->d_port = bpf_ntohs(info->d_port);
        BPF_CORE_READ_INTO(&d_addr_v6, s, __sk_common.skc_v6_daddr.in6_u.u6_addr8);

        info->d_h = *((u64 *)&d_addr_v6[0]);
        info->d_l = *((u64 *)&d_addr_v6[8]);

        info->s_h = *((u64 *)&s_addr_v6[0]);
        info->s_l = *((u64 *)&s_addr_v6[8]);

        bool source_ip4, target_ip4;

        // We need to normalize as IP4 if we have an IP4 address mapped as IPV6,
        // otherwise when we need to compare the TCP http connection info it may not match
        if ((source_ip4 = ipv4_mapped_ipv6(info->d_h, info->d_l))) {
            info->d_h = 0;
            info->d_l = (u32)(info->d_l >> 32);
        }

        if ((target_ip4 = ipv4_mapped_ipv6(info->s_h, info->s_l))) {
            info->s_h = 0;
            info->s_l = (u32)(info->s_l >> 32);
        }

        if (source_ip4 && target_ip4) {
            info->flags |= F_HTTP_IP4;
        } else {
            info->flags |= F_HTTP_IP6;
        }
    }    
}

#endif