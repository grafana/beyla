#ifndef TCP_INFO_HELPERS_H
#define TCP_INFO_HELPERS_H

#include "vmlinux.h"
#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "http_types.h"
#include "bpf_endian.h"

// Taken from uapi/linux/tcp.h
struct __tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
};

static __always_inline bool read_sk_buff(struct __sk_buff *skb, protocol_info_t *tcp, http_connection_info_t *http) {
    // we read the protocol just like here linux/samples/bpf/parse_ldabs.c
    u16 h_proto;
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto, sizeof(h_proto));
    h_proto = __bpf_htons(h_proto);

    u8 proto = 0;
    // do something similar as linux/samples/bpf/parse_varlen.c
    switch (h_proto) {
    case ETH_P_IP: {
        u8 hdr_len;
        // ip4 header lengths are variable
        // access ihl as a u8 (linux/include/linux/skbuff.h)
        bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
        hdr_len &= 0x0f;
        hdr_len *= 4;

        /* verify hlen meets minimum size requirements */
        if (hdr_len < sizeof(struct iphdr)) {
            return false;
        }

        // we read the ip header linux/samples/bpf/parse_ldabs.c and linux/samples/bpf/tcbpf1_kern.c
        // the level 4 protocol let's us only filter TCP packets, the ip protocol gets us the source
        // and destination IP pairs
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol), &proto, sizeof(proto));

        u32 saddr;
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), &saddr, sizeof(saddr));
        u32 daddr;
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr), &daddr, sizeof(daddr));

        __builtin_memcpy(http->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(http->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
        __builtin_memcpy(http->s_addr + sizeof(ip4ip6_prefix), &saddr, sizeof(saddr));
        __builtin_memcpy(http->d_addr + sizeof(ip4ip6_prefix), &daddr, sizeof(daddr));

        tcp->hdr_len = ETH_HLEN + hdr_len;
        break;
    }
    case ETH_P_IPV6:
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr), &proto, sizeof(proto));

        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, saddr), &http->s_addr, sizeof(http->s_addr));
        bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, daddr), &http->d_addr, sizeof(http->d_addr));

        tcp->hdr_len = ETH_HLEN + sizeof(struct ipv6hdr);
        break;
    default:
        return false;
    }

    if (proto != IPPROTO_TCP) {
        return false;
    }

    u16 port;
    bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, source), &port, sizeof(port));
    http->s_port = __bpf_htons(port);

    bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, dest), &port, sizeof(port));
    http->d_port = __bpf_htons(port);

    u16 seq;
    bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, seq), &seq, sizeof(seq));
    tcp->seq = __bpf_htons(seq);

    u8 doff;
    bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, ack_seq) + 4, &doff, sizeof(doff)); // read the first byte past __tcphdr->ack_seq, we can't do offsetof bit fields
    doff &= 0xf0; // clean-up res1
    doff >>= 4; // move the upper 4 bits to low
    doff *= 4; // convert to bytes length

    tcp->hdr_len += doff;

    u8 flags;
    bpf_skb_load_bytes(skb, tcp->hdr_len + offsetof(struct __tcphdr, ack_seq) + 4 + 1, &flags, sizeof(flags)); // read the second byte past __tcphdr->doff, again bit fields offsets
    tcp->flags = flags;

    if ((skb->len - tcp->hdr_len) < 0) { // less than 0 is a packet we can't parse
        return false;
    }

    return true;
}

static __always_inline bool tcp_close(protocol_info_t *tcp) {
    return tcp->flags & (TCPHDR_FIN | TCPHDR_RST);
}

static __always_inline bool tcp_ack(protocol_info_t *tcp) {
    return tcp->flags == TCPHDR_ACK;
}

static __always_inline bool tcp_empty(protocol_info_t *tcp, struct __sk_buff *skb) {
    return tcp->hdr_len == skb->len; 
}

#endif