#ifndef _TC_TRACER_L7
#define _TC_TRACER_L7

#include "utils.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "http_types.h"
#include "tc_common.h"
#include "tc_sock.h"
#include "bpf_dbg.h"
#include "tracing.h"

#define BPF_F_CURRENT_NETNS (-1)

typedef struct tp_buf_data {
    u8 buf[256];
} tp_buf_data_t;
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, tp_buf_data_t);
    __uint(max_entries, 1);
} tp_buf_memory SEC(".maps");

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

static __always_inline unsigned char *tp_buf_mem(tp_info_t *tp) {
    int zero = 0;
    tp_buf_data_t *val = (tp_buf_data_t *)bpf_map_lookup_elem(&tp_buf_memory, &zero);

    if (!val) {
        return 0;
    }

    __builtin_memcpy(val->buf, TP, EXTEND_SIZE);
    make_tp_string(val->buf + TP_PREFIX_SIZE, tp);

    return val->buf;
}

static __always_inline int l7_app_egress(struct __sk_buff *skb,
                                         tp_info_pid_t *tp,
                                         connection_info_t *conn,
                                         protocol_info_t *tcp) {
    bpf_skb_pull_data(skb, skb->len);

    void *data_end = ctx_data_end(skb);
    void *data = ctx_data(skb);
    struct ethhdr *eth = (struct ethhdr *)(data);
    struct bpf_sock_tuple *tuple;
    struct bpf_sock *sk;
    bool ipv4;

    if ((void *)(eth + 1) > data_end) {
        bpf_dbg_printk("bad size");
        return 0;
    }

    tuple = get_tuple(data, sizeof(*eth), data_end, eth->h_proto, &ipv4);
    //bpf_printk("tuple %llx, next %llx, data end %llx", tuple, (void *)((u8 *)tuple + sizeof(*tuple)), data_end);

    if (!tuple) {
        bpf_dbg_printk("bad tuple %llx, next %llx, data end %llx",
                       tuple,
                       (void *)(tuple + sizeof(struct bpf_sock_tuple)),
                       data_end);
    } else {
        if (ipv4 && (u64)((u8 *)tuple + sizeof(tuple->ipv4)) < (u64)data_end) {
            struct bpf_sock_tuple tup = {};
            __builtin_memcpy(&tup, tuple, sizeof(tup.ipv4));

            sk = bpf_sk_lookup_tcp(skb, &tup, sizeof(tup.ipv4), BPF_F_CURRENT_NETNS, 0);
            bpf_dbg_printk("sk=%d\n", sk ? 1 : 0);
            if (sk) {
                bpf_dbg_printk("LOOKUP %llx:%d ->", conn->s_ip[3], conn->s_port);
                bpf_dbg_printk("LOOKUP TO %llx:%d", conn->d_ip[3], conn->d_port);

                struct bpf_sock *sk1 = (struct bpf_sock *)bpf_map_lookup_elem(&sock_dir, conn);

                if (sk1) {
                    bpf_dbg_printk("Found sk1 %llx", sk1);
                    bpf_sk_release(sk1);
                } else {
                    bpf_map_update_elem(&sock_dir, conn, sk, BPF_NOEXIST);
                }

                bpf_sk_release(sk);
            }
        } else {
            bpf_dbg_printk("ipv6");
        }
    }

    u32 tot_len = (u64)ctx_data_end(skb) - (u64)ctx_data(skb);
    bpf_dbg_printk(
        "egress, tot_len %d, s_port %d, data_start %d", tot_len, conn->s_port, tcp->hdr_len);

    unsigned char *tp_buf = tp_buf_mem(&tp->tp);

    if (!tp_buf) {
        tp_buf = (unsigned char *)TP;
    }

    u32 s_port = conn->s_port;
    tc_http_ctx_t *ctx = (tc_http_ctx_t *)bpf_map_lookup_elem(&tc_http_ctx_map, &s_port);
    if (ctx) {
        u32 packet_size = tot_len - tcp->hdr_len;
        bpf_dbg_printk("Found it! packet_size %d, offset %d", packet_size, ctx->offset);
        bpf_dbg_printk("seen %d, written %d", ctx->seen, ctx->written);

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
                        __builtin_memcpy(start, tp_buf, EXTEND_SIZE);
                        bpf_dbg_printk("Set the string fast_path!");
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
                    buf_memcpy((char *)start, (char *)tp_buf + tp_off, len, ctx_data_end(skb));
                    bpf_dbg_printk("Set the string off = %d, len = %d!", tp_off, len);
                }

                ctx->written += len;
                if (ctx->written >= EXTEND_SIZE) {
                    bpf_map_delete_elem(&tc_http_ctx_map, &s_port);
                }
            }
        }
    }

    return 0;
}

#endif // _TC_TRACER_L7