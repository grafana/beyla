#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_core_read.h>

#include <common/http_types.h>
#include <common/protocol_defs.h>

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
        BPF_CORE_READ_INTO(
            &info->s_port, s, __sk_common.skc_num); // weirdly not in network byte order
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
        BPF_CORE_READ_INTO(
            &info->s_port, s, __sk_common.skc_num); // weirdly not in network byte order
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

    struct socket *sock = (struct socket *)(args->addr);
    BPF_CORE_READ_INTO(&s, sock, sk);

    return parse_sock_info(s, info);
}

static __always_inline bool parse_connect_sock_info(sock_args_t *args, connection_info_t *info) {
    return parse_sock_info((struct sock *)(args->addr), info);
}

static __always_inline u16 get_sockaddr_port(struct sockaddr *addr) {
    short unsigned int sa_family;

    BPF_CORE_READ_INTO(&sa_family, addr, sa_family);
    u16 bport = 0;

    //bpf_dbg_printk("addr = %llx, sa_family %d", addr, sa_family);

    if (sa_family == AF_INET) {
        struct sockaddr_in *baddr = (struct sockaddr_in *)addr;
        BPF_CORE_READ_INTO(&bport, baddr, sin_port);
        bport = bpf_ntohs(bport);
    } else if (sa_family == AF_INET6) {
        struct sockaddr_in6 *baddr = (struct sockaddr_in6 *)addr;
        BPF_CORE_READ_INTO(&bport, baddr, sin6_port);
        bport = bpf_ntohs(bport);
    }

    return bport;
}

static __always_inline u16 get_sockaddr_port_user(struct sockaddr *addr) {
    short unsigned int sa_family;

    bpf_probe_read(&sa_family, sizeof(short unsigned int), &addr->sa_family);
    u16 bport = 0;

    //bpf_dbg_printk("addr = %llx, sa_family %d", addr, sa_family);

    if (sa_family == AF_INET) {
        bpf_probe_read(&bport, sizeof(u16), &(((struct sockaddr_in *)addr)->sin_port));
    } else if (sa_family == AF_INET6) {
        bpf_probe_read(&bport, sizeof(u16), &(((struct sockaddr_in6 *)addr)->sin6_port));
    }

    bport = bpf_ntohs(bport);

    return bport;
}
