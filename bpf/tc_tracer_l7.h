#ifndef _TC_TRACER_L7
#define _TC_TRACER_L7

#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "http_types.h"
#include "tc_common.h"
#include "tc_sock.h"

#define BPF_F_CURRENT_NETNS (-1)

static struct bpf_sock_tuple *
get_tuple(void *data, __u64 nh_off, void *data_end, __u16 eth_proto, bool *ipv4) {
    struct bpf_sock_tuple *result;
    __u64 ihl_len = 0;
    __u8 proto = 0;

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(data + nh_off);

        if ((void *)(iph + 1) > data_end) {
            return 0;
        }

        ihl_len = iph->ihl * 4;
        proto = iph->protocol;
        *ipv4 = true;
        result = (struct bpf_sock_tuple *)&iph->saddr;
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + nh_off);

        if ((void *)(ip6h + 1) > data_end) {
            return 0;
        }

        ihl_len = sizeof(*ip6h);
        proto = ip6h->nexthdr;
        *ipv4 = true;
        result = (struct bpf_sock_tuple *)&ip6h->saddr;
    }

    if (data + nh_off + ihl_len > data_end || proto != IPPROTO_TCP) {
        return 0;
    }

    return result;
}

static __always_inline int buf_memcpy(char *dest, char *src, s32 size, void *end) {
    u32 rem = size;
    for (int i = 0; (i < ((EXTEND_SIZE / 8) + 1)) && (rem >= 8); i++) {
        if ((void *)(dest + 8) <= end) {
            *(u64 *)(dest) = *(u64 *)(src);
        } else {
            break;
        }
        rem -= 8;
        dest += 8;
        src += 8;
    }

    for (int i = 0; (i < 8) && (rem > 0); i++) {
        if ((void *)(dest + 1) <= end) {
            *dest = *src;
        } else {
            break;
        }
        rem--;
        dest++;
        src++;
    }

    return 0;
}

static __always_inline int
l7_app_egress(struct __sk_buff *skb, connection_info_t *conn, protocol_info_t *tcp) {
    bpf_skb_pull_data(skb, skb->len);

    void *data_end = ctx_data_end(skb);
    void *data = ctx_data(skb);
    struct ethhdr *eth = (struct ethhdr *)(data);
    struct bpf_sock_tuple *tuple;
    struct bpf_sock *sk;
    bool ipv4;

    if ((void *)(eth + 1) > data_end) {
        bpf_printk("bad size");
        return 0;
    }

    tuple = get_tuple(data, sizeof(*eth), data_end, eth->h_proto, &ipv4);
    //bpf_printk("tuple %llx, next %llx, data end %llx", tuple, (void *)((u8 *)tuple + sizeof(*tuple)), data_end);

    if (!tuple) {
        bpf_printk("bad tuple %llx, next %llx, data end %llx",
                   tuple,
                   (void *)(tuple + sizeof(struct bpf_sock_tuple)),
                   data_end);
    } else {
        if (ipv4 && (u64)((u8 *)tuple + sizeof(tuple->ipv4)) < (u64)data_end) {
            struct bpf_sock_tuple tup = {};
            __builtin_memcpy(&tup, tuple, sizeof(tup.ipv4));

            sk = bpf_sk_lookup_tcp(skb, &tup, sizeof(tup.ipv4), BPF_F_CURRENT_NETNS, 0);
            bpf_printk("sk=%d\n", sk ? 1 : 0);
            if (sk) {
                bpf_printk("LOOKUP %llx:%d -> %llx:%d",
                           conn->s_ip[3],
                           conn->s_port,
                           conn->d_ip[3],
                           conn->d_port);

                struct bpf_sock *sk1 = (struct bpf_sock *)bpf_map_lookup_elem(&sock_dir, conn);

                if (sk1) {
                    bpf_printk("Found sk1 %llx", sk1);
                    bpf_sk_release(sk1);
                } else {
                    if (bpf_map_update_elem(&sock_dir, conn, sk, BPF_NOEXIST)) {
                        bpf_printk("Failed to update map");
                    }
                }

                bpf_sk_release(sk);
            }
        } else {
            bpf_printk("ipv6");
        }
    }

    u32 tot_len = (u64)ctx_data_end(skb) - (u64)ctx_data(skb);
    bpf_printk("egress, len %d, s_port %d, data_start %d, len = %d",
               tot_len,
               conn->s_port,
               tcp->hdr_len,
               tot_len - tcp->hdr_len);

    u32 s_port = conn->s_port;
    tc_http_ctx_t *ctx = (tc_http_ctx_t *)bpf_map_lookup_elem(&tc_http_ctx_map, &s_port);
    if (ctx) {
        u32 packet_size = tot_len - tcp->hdr_len;
        bpf_printk("Found it! packet_size %d, offset %d", packet_size, ctx->offset);
        bpf_printk("seen %d, written %d", ctx->seen, ctx->written);

        if (packet_size > 0) {
            u32 len = 0;
            u32 off = tcp->hdr_len;
            // picked a value large enough to support TCP headers
            bpf_clamp_umax(off, 128);
            void *start = ctx_data(skb) + off;

            if (ctx->seen < ctx->offset) {
                u32 diff = ctx->offset - ctx->seen;
                if (diff <= packet_size) {
                    ctx->seen += packet_size;
                    return 0;
                } else {
                    len = packet_size - diff;
                    bpf_clamp_umax(len, EXTEND_SIZE);
                }
            } else {
                // Fast path
                if (ctx->written == 0 && packet_size == EXTEND_SIZE) {
                    if ((start + EXTEND_SIZE) <= ctx_data_end(skb)) {
                        __builtin_memcpy(start, (char *)TP, EXTEND_SIZE);
                        bpf_printk("Set the string fast_path!");
                        bpf_map_delete_elem(&tc_http_ctx_map, &s_port);
                        return 0;
                    }
                }

                if (ctx->written <= EXTEND_SIZE) {
                    len = EXTEND_SIZE - ctx->written;
                    bpf_clamp_umax(len, EXTEND_SIZE);

                    if (len > packet_size) {
                        len = packet_size;
                    }
                } else {
                    bpf_map_delete_elem(&tc_http_ctx_map, &s_port);
                    return 0;
                }
            }

            if (len > 0) {
                u32 tp_off = ctx->written;
                bpf_clamp_umax(tp_off, EXTEND_SIZE);
                bpf_clamp_umax(len, EXTEND_SIZE);

                if ((start + len) <= ctx_data_end(skb)) {
                    buf_memcpy((char *)start, (char *)TP + tp_off, len, ctx_data_end(skb));
                    bpf_printk("Set the string off = %d, len = %d!", tp_off, len);
                }

                ctx->written += len;
                if (len == EXTEND_SIZE) {
                    bpf_map_delete_elem(&tc_http_ctx_map, &s_port);
                }
            }
        }
    }

    return 0;
}

#endif // _TC_TRACER_L7