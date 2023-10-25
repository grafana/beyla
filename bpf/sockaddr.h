#ifndef SOCKADDR_HELPERS_H
#define SOCKADDR_HELPERS_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf_core_read.h"
#include "http_types.h"
#include "http_defs.h"

typedef struct accept_args {
    u64 addr; // linux sock or socket address
    u64 accept_time;
} sock_args_t;

static __always_inline bool parse_sock_info(struct sock *s, connection_info_t *info) {
    short unsigned int skc_family;
    BPF_CORE_READ_INTO(&skc_family, s, __sk_common.skc_family);
    
    // We always store the IP addresses in IPV6 format, simplifies the code and
    // it matches natively what our Golang userspace processing will require.
    if (skc_family == AF_INET) {
        u32 ip4_s_l;
        u32 ip4_d_l;
        BPF_CORE_READ_INTO(&info->s_port, s, __sk_common.skc_num); // weirdly not in network byte order
        BPF_CORE_READ_INTO(&ip4_s_l, s, __sk_common.skc_rcv_saddr);        
        BPF_CORE_READ_INTO(&info->d_port, s, __sk_common.skc_dport);
        info->d_port = bpf_ntohs(info->d_port);
        BPF_CORE_READ_INTO(&ip4_d_l, s, __sk_common.skc_daddr);

        __builtin_memcpy(info->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(info->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(info->s_addr + sizeof(ip4ip6_prefix), &ip4_s_l, sizeof(ip4_s_l));
        __builtin_memcpy(info->d_addr + sizeof(ip4ip6_prefix), &ip4_d_l, sizeof(ip4_d_l));

        return true;
    } else if (skc_family == AF_INET6) {
        BPF_CORE_READ_INTO(&info->s_port, s, __sk_common.skc_num); // weirdly not in network byte order
        BPF_CORE_READ_INTO(&info->s_addr, s, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&info->d_port, s, __sk_common.skc_dport);
        info->d_port = bpf_ntohs(info->d_port);
        BPF_CORE_READ_INTO(&info->d_addr, s, __sk_common.skc_v6_daddr.in6_u.u6_addr8);

        return true;
    }

    return false;
}

// We tag the server and client calls in flags to avoid mistaking a mutual connection between two
// services as the same connection info. It would be almost impossible, but it might happen.
static __always_inline bool parse_accept_socket_info(sock_args_t *args, connection_info_t *info) {
    struct sock *s;

    struct socket *sock = (struct socket*)(args->addr);
    BPF_CORE_READ_INTO(&s, sock, sk);

    return parse_sock_info(s, info);
}

static __always_inline bool parse_connect_sock_info(sock_args_t *args, connection_info_t *info) {
    return parse_sock_info((struct sock*)(args->addr), info);
}

#endif