#include <vmlinux.h>

#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum { TC_ACT_OK = 0 };
enum { MAX_IP_PACKET_SIZE = 0x7fff };
enum { MAX_INLINE_LEN = 0x7ff };

struct seq_offset_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 10240);
} seq_offset_map SEC(".maps");

const char TP[] = "Beyla-TP: ABCDEF\r\n";
const __u32 EXTEND_SIZE = sizeof(TP) - 1;

struct datasum_loop_ctx {
    const unsigned char *b;
    const unsigned char *e;
    __u32 *sum;
};

static long calculate_datasum_loop(__u32 index, void *ctx) {
    if (index % 2 == 1) {
        return 0;
    }

    index &= MAX_IP_PACKET_SIZE;

    const struct datasum_loop_ctx *lctx = (const struct datasum_loop_ctx *)ctx;

    const unsigned char *b = lctx->b;
    const unsigned char *e = lctx->e;
    __u32 *sum = lctx->sum;

    if (!b) {
        return 1;
    }

    if (&b[index] + sizeof(__u16) > e) {
        return 1;
    }

    __u16 word;

    __builtin_memcpy(&word, &b[index], sizeof(word));

    *sum += word;

    return 0;
}

static __always_inline void
calculate_datasum(const unsigned char *b, const unsigned char *e, __u32 *sum) {
    if (b >= e) {
        *sum = 0;
        return;
    }

    const __u32 len = (e - b) & MAX_IP_PACKET_SIZE;

    struct datasum_loop_ctx datasum_loop_ctx = {b, e, sum};

    bpf_loop(len, calculate_datasum_loop, &datasum_loop_ctx, 0);

    if (len % 2 == 1) {
        if (&b[len - 1] >= e) {
            *sum = 0;
            return;
        }

        __u16 word = 0;
        __builtin_memcpy(&word, &b[len - 1], 1);

        *sum += word;
    }

    while (*sum >> 16) {
        *sum = (*sum & 0xFFFF) + (*sum >> 16);
    }
}

static __always_inline void
calculate_datasum_inline(const unsigned char *b, const unsigned char *e, __u32 *sum) {
    if (b >= e) {
        *sum = 0;
        return;
    }

    const __u32 len = (e - b) & MAX_INLINE_LEN;

    for (__u32 i = 0; i < len; i += 2) {
        if (&b[i] + 1 >= e) {
            break;
        }

        __u16 word;

        __builtin_memcpy(&word, &b[i], 2);

        *sum += word;
    }

    if (len % 2 == 1) {
        if (&b[len - 1] >= e) {
            *sum = 0;
            return;
        }

        __u16 word = 0;
        __builtin_memcpy(&word, &b[len - 1], 1);

        *sum += word;
    }

    while (*sum >> 16) {
        *sum = (*sum & 0xFFFF) + (*sum >> 16);
    }
}

static __always_inline void *ctx_data(struct __sk_buff *ctx) {
    void *data;

    asm("%[res] = *(u32 *)(%[base] + %[offset])"
        : [res] "=r"(data)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct __sk_buff, data)), "m"(*ctx));

    return data;
}

static __always_inline void *ctx_data_end(struct __sk_buff *ctx) {
    void *data_end;

    asm("%[res] = *(u32 *)(%[base] + %[offset])"
        : [res] "=r"(data_end)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct __sk_buff, data_end)), "m"(*ctx));

    return data_end;
}

[[maybe_unused]] static __always_inline struct ethhdr *eth_header(struct __sk_buff *ctx) {
    void *data = ctx_data(ctx);

    return (data + sizeof(struct ethhdr) > ctx_data_end(ctx)) ? NULL : data;
}

static __always_inline struct iphdr *ip_header(struct __sk_buff *ctx) {
    void *data = ctx_data(ctx);

    data += sizeof(struct ethhdr);

    return (data + sizeof(struct iphdr) > ctx_data_end(ctx)) ? NULL : data;
}

static __always_inline struct tcphdr *tcp_header(struct __sk_buff *ctx) {
    void *data = ctx_data(ctx);

    data += sizeof(struct ethhdr) + sizeof(struct iphdr);

    return (data + sizeof(struct tcphdr) > ctx_data_end(ctx)) ? NULL : data;
}

static __always_inline unsigned char *tcp_payload(struct __sk_buff *ctx) {
    struct tcphdr *tcp = tcp_header(ctx);

    if (!tcp) {
        return NULL;
    }

    unsigned char *payload = (unsigned char *)tcp;

    payload += tcp->doff * 4;

    if ((void *)payload > ctx_data_end(ctx)) {
        return NULL;
    }

    return payload;
}

static __always_inline int update_tcp_csum(struct __sk_buff *ctx) {
    const struct iphdr *iph = ip_header(ctx);

    if (!iph) {
        return 0;
    }

    struct tcphdr *tcp = tcp_header(ctx);

    if (!tcp) {
        return 0;
    }

    const unsigned char *b = (const unsigned char *)tcp;
    const unsigned char *e = (const unsigned char *)ctx_data_end(ctx);

    tcp->check = 0;

    const __u16 tcp_len = (e - b) & MAX_IP_PACKET_SIZE;

    __u32 data_sum = 0;

    __u32 pseudo_header[3];
    pseudo_header[0] = iph->saddr;
    pseudo_header[1] = iph->daddr;
    pseudo_header[2] = bpf_htonl((6 << 16) | tcp_len);

    calculate_datasum_inline(
        (unsigned char *)&pseudo_header, (unsigned char *)&pseudo_header[3], &data_sum);

    if (tcp_len < MAX_INLINE_LEN) {
        calculate_datasum_inline((unsigned char *)tcp, e, &data_sum);
    } else {
        calculate_datasum((unsigned char *)tcp, e, &data_sum);
    }

    const __u16 tcp_csum = (__u16)~data_sum;

    tcp = tcp_header(ctx);

    if (!tcp) {
        return 0;
    }

    tcp->check = tcp_csum;

    return 1;
}

static __always_inline long update_ip_csum(struct __sk_buff *ctx) {
    struct iphdr *iph = ip_header(ctx);

    if (!iph) {
        return -1;
    }

    const __u16 new_total_len = bpf_ntohs(iph->tot_len) + EXTEND_SIZE;
    const __be16 ip_tot_len_old = iph->tot_len;
    const __be16 ip_tot_len_new = bpf_htons(new_total_len);

    const __u32 ip_csum_off = (sizeof(struct ethhdr) + offsetof(struct iphdr, check)) & 0xff;

    return bpf_l3_csum_replace(
        ctx, ip_csum_off, ip_tot_len_old, ip_tot_len_new, sizeof(ip_tot_len_new));
}

static __always_inline __u32 extra_xmited_bytes(__u32 key) {
    const __u32 *seq = bpf_map_lookup_elem(&seq_offset_map, &key);

    return seq ? *seq : 0;
}

static __always_inline int is_http_request(struct __sk_buff *ctx) {
    unsigned char *payload = tcp_payload(ctx);

    if (!payload) {
        return 0;
    }

    char req_buf[] = "OPTIONS /"; // largest HTTP request operation

    const __u32 offset = (void *)payload - ctx_data(ctx);

    if (bpf_skb_load_bytes(ctx, offset, &req_buf, sizeof(req_buf) - 1) != 0) {
        return 0;
    }

    return req_buf[0] == 'G' && req_buf[1] == 'E' && req_buf[2] == 'T' && req_buf[3] == ' ' &&
               req_buf[4] == '/' ||
           req_buf[0] == 'P' && req_buf[1] == 'O' && req_buf[2] == 'S' && req_buf[3] == 'T' &&
               req_buf[4] == ' ' && req_buf[5] == '/' ||
           req_buf[0] == 'P' && req_buf[1] == 'U' && req_buf[2] == 'T' && req_buf[3] == ' ' &&
               req_buf[4] == '/' ||
           req_buf[0] == 'P' && req_buf[1] == 'A' && req_buf[2] == 'T' && req_buf[3] == 'C' &&
               req_buf[4] == 'H' && req_buf[5] == ' ' && req_buf[5] == '/' ||
           req_buf[0] == 'D' && req_buf[1] == 'E' && req_buf[2] == 'L' && req_buf[3] == 'E' &&
               req_buf[4] == 'T' && req_buf[5] == 'E' && req_buf[6] == ' ' && req_buf[7] == '/' ||
           req_buf[0] == 'H' && req_buf[1] == 'E' && req_buf[2] == 'A' && req_buf[3] == 'D' &&
               req_buf[4] == ' ' && req_buf[5] == '/' ||
           req_buf[0] == 'O' && req_buf[1] == 'P' && req_buf[1] == 'T' && req_buf[1] == 'I' &&
               req_buf[1] == 'O' && req_buf[1] == 'N' && req_buf[1] == 'S' && req_buf[1] == ' ' &&
               req_buf[1] == '/';
}

static __always_inline unsigned char *
memchar(unsigned char *haystack, char needle, unsigned char *end, __u32 size) {
    for (__u32 i = 0; i < size; ++i) {
        if (&haystack[i] >= end) {
            break;
        }

        if (haystack[i] == needle) {
            return &haystack[i];
        }
    }

    return NULL;
}

struct memmove_loop_ctx {
    unsigned char *dst;
    unsigned char *src;

    const unsigned char *end;

    __u32 size;
};

static long memmove_loop(__u32 index, void *ctx) {
    struct memmove_loop_ctx *lctx = (struct memmove_loop_ctx *)ctx;

    if (index == lctx->size) {
        return 1;
    }

    const __u32 i = (lctx->size - index) & MAX_IP_PACKET_SIZE;

    const unsigned char *end = lctx->end;

    unsigned char *src = &lctx->src[i];

    if (src > end) {
        return 1;
    }

    unsigned char *dst = &lctx->dst[i];

    if (dst > end) {
        return 1;
    }

    *(dst - 1) = *(src - 1);

    return 0;
}

static __always_inline void
move_data(unsigned char *dst, unsigned char *src, const unsigned char *end, __u32 size) {
    struct memmove_loop_ctx memmove_loop_ctx = {dst, src, end, size};

    bpf_loop(size, memmove_loop, &memmove_loop_ctx, 0);
}

static __always_inline unsigned char *
find_first_of(unsigned char *begin, unsigned char *end, char ch) {
    return memchar(begin, ch, end, MAX_INLINE_LEN);
}

static __always_inline int extend_skb(struct __sk_buff *ctx) {
    bpf_skb_pull_data(ctx, ctx->len);

    // find first \n

    unsigned char *payload = tcp_payload(ctx);

    if (!payload) {
        return 0;
    }

    const unsigned char *newline = find_first_of(payload, ctx_data_end(ctx), '\n');

    if (!newline) {
        return 0;
    }

    const __u32 copy_size = ((unsigned char *)ctx_data_end(ctx) - newline - 1) & MAX_IP_PACKET_SIZE;
    const __u32 nl_offset = newline - payload;

    if (bpf_skb_change_tail(ctx, ctx->len + EXTEND_SIZE, 0) != 0) {
        return 0;
    }

    bpf_skb_pull_data(ctx, ctx->len);

    payload = tcp_payload(ctx);

    if (!payload) {
        return 0;
    }

    const unsigned char *end = ctx_data_end(ctx);

    //bpf_printk("copy size: %u\n", copy_size);

    unsigned char *src = payload + nl_offset + 1;
    unsigned char *dest = src + EXTEND_SIZE;

    if (dest + copy_size > end) {
        return 0;
    }

    move_data(dest, src, end, copy_size);

    if (src + sizeof(TP) - 1 > end) {
        return 0;
    }

    __builtin_memcpy(src, TP, sizeof(TP) - 1);

    payload = tcp_payload(ctx);

    if ((void *)payload > ctx_data_end(ctx)) {
        return 0;
    }

    update_ip_csum(ctx);

    struct iphdr *iph = ip_header(ctx);

    if (!iph) {
        return 0;
    }

    iph->tot_len = bpf_htons(bpf_ntohs(iph->tot_len) + EXTEND_SIZE);

    return update_tcp_csum(ctx);
}

static __always_inline void update_tcp_seq(struct __sk_buff *ctx, __u32 extra_bytes) {
    if (extra_bytes == 0) {
        return;
    }

    struct tcphdr *tcp = tcp_header(ctx);

    if (!tcp) {
        return;
    }

    __u32 seq = bpf_ntohl(tcp->seq);
    seq += extra_bytes;
    tcp->seq = bpf_htonl(seq);
}

SEC("tc_egress")
int tc_http_egress(struct __sk_buff *ctx) {
    struct tcphdr *tcp = tcp_header(ctx);

    if (!tcp) {
        return TC_ACT_OK;
    }

    const __u16 src_port = bpf_ntohs(tcp->source);
    const __u16 dst_port = bpf_ntohs(tcp->dest);

    if (dst_port != 8080 && dst_port != 80) {
        return TC_ACT_OK;
    }

    __u32 extra_bytes = extra_xmited_bytes(src_port);

    update_tcp_seq(ctx, extra_bytes);

    if (!is_http_request(ctx)) {
        return TC_ACT_OK;
    }

    if (!extend_skb(ctx)) {
        return TC_ACT_OK;
    }

    const __u32 key = src_port;

    extra_bytes += EXTEND_SIZE;

    if (bpf_map_update_elem(&seq_offset_map, &key, &extra_bytes, BPF_ANY) != 0) {
        bpf_printk("failed to update map with value %u", extra_bytes);
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

SEC("tc_ingress")
int tc_http_ingress(struct __sk_buff *ctx) {
    struct tcphdr *tcp = tcp_header(ctx);

    if (!tcp) {
        return TC_ACT_OK;
    }

    const __u16 dst_port = bpf_ntohs(tcp->dest);

    const __u32 key = dst_port;
    const __u32 *seq = bpf_map_lookup_elem(&seq_offset_map, &key);

    if (!seq) {
        return TC_ACT_OK;
    }

    __u32 ack_seq = bpf_ntohl(tcp->ack_seq);
    ack_seq -= *seq;

    tcp->ack_seq = bpf_htonl(ack_seq);

    return TC_ACT_OK;
}
