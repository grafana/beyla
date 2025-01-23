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

// Temporary memory we'll use to make the 'Traceparent: ...' value.
typedef struct tp_buf_data {
    u8 buf[256];
} tp_buf_data_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, tp_buf_data_t);
    __uint(max_entries, 1);
} tp_buf_memory SEC(".maps");

// We use this helper to read in the connection tuple information in the
// bpf_sock_tuple format. We use this struct to add sockets which are
// established before we launched Beyla, since we'll not see them in the
// sock_ops program which tracks them.
static __always_inline struct bpf_sock_tuple *
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

// A version of __builtin_memcpy which works with a variable size
static __always_inline int buf_memcpy(char *dest, char *src, s32 size, void *end) {
    u32 rem = size;
    // Copy 8 bytes at a time while you can
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

    // Finish the remainder one by one
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

static __always_inline void l7_app_ctx_cleanup(egress_key_t *e_key) {
    bpf_map_delete_elem(&tc_http_ctx_map, &e_key->s_port);
    bpf_map_delete_elem(&outgoing_trace_map, e_key);
}

static __always_inline struct bpf_sock *lookup_sock_from_tuple(struct __sk_buff *skb,
                                                               struct bpf_sock_tuple *tuple,
                                                               bool ipv4,
                                                               void *data_end) {
    if (ipv4 && (u64)((u8 *)tuple + sizeof(tuple->ipv4)) < (u64)data_end) {
        // Lookup to see if you can find a socket for this tuple in the
        // kernel socket tracking. We look up in all namespaces (-1).
        return bpf_sk_lookup_tcp(skb, tuple, sizeof(tuple->ipv4), BPF_F_CURRENT_NETNS, 0);
    } else if (!ipv4 && (u64)((u8 *)tuple + sizeof(tuple->ipv6)) < (u64)data_end) {
        return bpf_sk_lookup_tcp(skb, tuple, sizeof(tuple->ipv6), BPF_F_CURRENT_NETNS, 0);
    }

    return 0;
}

static __always_inline int write_traceparent(struct __sk_buff *skb,
                                             protocol_info_t *tcp,
                                             egress_key_t *e_key,
                                             tc_http_ctx_t *ctx,
                                             unsigned char *tp_buf) {
    u32 tot_len = (u64)ctx_data_end(skb) - (u64)ctx_data(skb);
    u32 packet_size = tot_len - tcp->hdr_len;
    bpf_dbg_printk("Writing traceparent packet_size %d, offset %d, tot_len %d",
                   packet_size,
                   ctx->offset,
                   tot_len);
    bpf_dbg_printk("seen %d, written %d", ctx->seen, ctx->written);

    if (packet_size > 0) {
        u32 len = 0;
        u32 off = tcp->hdr_len;
        // picked a value large enough to support TCP headers
        bpf_clamp_umax(off, 128);
        void *start = ctx_data(skb) + off;

        // We haven't seen enough bytes coming through from the start
        // until we did the split (at ctx->offset is where we injected)
        // the empty space.
        if (ctx->seen < ctx->offset) {
            // Diff = How much more before we cross offset
            u32 diff = ctx->offset - ctx->seen;
            // We received less or equal bytes to what we want to
            // reach ctx->offset, i.e the split point.
            if (diff > packet_size) {
                ctx->seen += packet_size;
                return 0;
            } else {
                // We went over the split point, calculate how much can we
                // write, but cap it to the max size = 70 bytes.
                bpf_clamp_umax(diff, 2048);
                start += diff;
                ctx->seen = ctx->offset;
                len = packet_size - diff;
                bpf_clamp_umax(len, EXTEND_SIZE);
            }
        } else {
            // Fast path. We are exactly at the offset, we've written
            // nothing of the 'Traceparent: ...' text yet and the packet
            // is exactly 70 bytes.
            if (ctx->written == 0 && packet_size == EXTEND_SIZE) {
                if ((start + EXTEND_SIZE) <= ctx_data_end(skb)) {
                    __builtin_memcpy(start, tp_buf, EXTEND_SIZE);
                    bpf_dbg_printk("Set the string fast_path!");
                    l7_app_ctx_cleanup(e_key);
                    return 0;
                }
            }

            // Nope, we've written some bytes in another packet and we
            // are not done writing yet.
            if (ctx->written < EXTEND_SIZE) {
                len = EXTEND_SIZE - ctx->written;
                bpf_clamp_umax(len, EXTEND_SIZE);

                if (len > packet_size) {
                    len = packet_size;
                }
            } else {
                // We've written everything already, just clean up
                l7_app_ctx_cleanup(e_key);
                return 0;
            }
        }

        if (len > 0) {
            u32 tp_off = ctx->written;
            // Keeps verifier happy
            bpf_clamp_umax(tp_off, EXTEND_SIZE);
            bpf_clamp_umax(len, EXTEND_SIZE);

            if ((start + len) <= ctx_data_end(skb)) {
                buf_memcpy((char *)start, (char *)tp_buf + tp_off, len, ctx_data_end(skb));
                bpf_dbg_printk("Set the string off = %d, len = %d!", tp_off, len);
            }

            ctx->written += len;
            // If we've written the full string this time around
            // cleanup the metadata.
            if (ctx->written >= EXTEND_SIZE) {
                l7_app_ctx_cleanup(e_key);
            }
        }
    }

    return 0;
}

// This function does two things:
//   1. It adds sockets in the socket hash map which have already been
//      established and we see them for the first time in Traffic Control, i.e
//      we are using them, but they weren't seen by the sock_ops.
//   2. It writes the 'Traceparent: ...' value setup as space for us by
//      the sock_msg program.
static __always_inline int l7_app_egress(struct __sk_buff *skb,
                                         tp_info_pid_t *tp,
                                         connection_info_t *conn,
                                         protocol_info_t *tcp,
                                         egress_key_t *e_key) {
    bpf_skb_pull_data(skb, skb->len);

    void *data_end = ctx_data_end(skb);
    void *data = ctx_data(skb);

    u32 s_port = e_key->s_port;
    tc_http_ctx_t *ctx = (tc_http_ctx_t *)bpf_map_lookup_elem(&tc_http_ctx_map, &s_port);

    if (!ctx) {
        struct ethhdr *eth = (struct ethhdr *)(data);
        bool ipv4;

        if ((void *)(eth + 1) > data_end) {
            bpf_dbg_printk("bad size");
            return 0;
        }

        // Get the bpf_sock_tuple value so we can look up and see if we don't have
        // this socket yet in our map.
        struct bpf_sock_tuple *tuple = get_tuple(data, sizeof(*eth), data_end, eth->h_proto, &ipv4);
        //bpf_printk("tuple %llx, next %llx, data end %llx", tuple, (void *)((u8 *)tuple + sizeof(*tuple)), data_end);

        if (!tuple) {
            bpf_dbg_printk("bad tuple %llx, next %llx, data end %llx",
                           tuple,
                           (void *)(tuple + sizeof(struct bpf_sock_tuple)),
                           data_end);
        } else {
            struct bpf_sock *sk = lookup_sock_from_tuple(skb, tuple, ipv4, data_end);
            bpf_dbg_printk("sk=%d\n", sk ? 1 : 0);
            if (sk) {
                bpf_dbg_printk("LOOKUP %llx:%d ->", conn->s_ip[3], conn->s_port);
                bpf_dbg_printk("LOOKUP TO %llx:%d", conn->d_ip[3], conn->d_port);

                // Query the socket map to see if have added this socket.
                struct bpf_sock *sk1 = (struct bpf_sock *)bpf_map_lookup_elem(&sock_dir, conn);

                // We found the socket, all good it was caught by the sock_ops,
                // just release it.
                if (sk1) {
                    bpf_dbg_printk("Found sk1 %llx", sk1);
                    bpf_sk_release(sk1);
                } else {
                    // First time we see a socket, add it to the map, it will
                    // get tracked on the next request
                    bpf_map_update_elem(&sock_dir, conn, sk, BPF_NOEXIST);
                }

                // We must release the reference to the original socket we looked up.
                bpf_sk_release(sk);
            }
        }
    }

    bpf_dbg_printk("egress, s_port %d, data_start %d", conn->s_port, tcp->hdr_len);

    unsigned char *tp_buf = tp_buf_mem(&tp->tp);

    if (!tp_buf) {
        tp_buf = (unsigned char *)TP;
    }

    // This is where the writing of the 'Traceparent: ...' field happens at L7.
    // Our packets are split by sock_msg like this:
    // [before the injected header],[70 bytes for 'Traceparent...'],[the rest]
    // This how it always looks when I tested, but I'm not sure if it's always
    // the case, seems plausible, but then the code below tries to handle any
    // split. The 'fast path' handles the exact split as above.
    if (ctx) {
        return write_traceparent(skb, tcp, e_key, ctx, tp_buf);
    }

    return 0;
}

#endif // _TC_TRACER_L7