//go:build beyla_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/go_addr_key.h>
#include <logger/bpf_dbg.h>

#include <maps/go_ongoing_http.h>
#include <maps/go_ongoing_http_client_requests.h>
#include <maps/ongoing_http.h>
#include <maps/sock_dir.h>

#include <common/http_types.h>
#include <common/tcp_info.h>
#include <common/tc_act.h>
#include <common/tc_common.h>

#include <tctracer/tc_ip.h>

static const u64 BPF_F_CURRENT_NETNS = -1;

enum protocol : u8 { protocol_ip4, protocol_ip6, protocol_unknown };

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("tc_ingress")
int beyla_app_ingress(struct __sk_buff *skb) {
    //bpf_printk("ingress");

    protocol_info_t tcp = {};
    connection_info_t conn = {};

    if (!read_sk_buff(skb, &tcp, &conn)) {
        return TC_ACT_UNSPEC;
    }

    if (tcp_ack(&tcp)) { // ack field must be set, which means we are looking at non SYN packet
        // assumes we are the only ones that added options, this can be improved
        if (tcp.h_proto == ETH_P_IP && tcp.ip_len == MIN_IP_LEN + MAX_TC_TP_LEN) {
            parse_ip_options_ipv4(skb, &conn, &tcp);
        } else if (tcp.h_proto == ETH_P_IPV6 &&
                   tcp.l4_proto == IP_V6_DEST_OPTS) { // Destination options used
            parse_ip_options_ipv6(skb, &conn, &tcp);
        }
    }

    return TC_ACT_UNSPEC;
}

static __always_inline void update_outgoing_request_span_id(pid_connection_info_t *p_conn,
                                                            protocol_info_t *tcp,
                                                            tp_info_pid_t *tp,
                                                            const egress_key_t *e_key) {
    http_info_t *h_info = bpf_map_lookup_elem(&ongoing_http, p_conn);
    if (h_info && tp->valid) {
        bpf_dbg_printk("Found HTTP info, resetting the span id to %x%x", tcp->seq, tcp->ack);
        populate_span_id_from_tcp_info(&h_info->tp, tcp);
    }

    go_addr_key_t *g_key = bpf_map_lookup_elem(&go_ongoing_http, e_key);
    if (g_key) {
        bpf_dbg_printk("Found Go HTTP info, trying to find the span id");
        http_func_invocation_t *invocation =
            bpf_map_lookup_elem(&go_ongoing_http_client_requests, g_key);
        if (invocation) {
            bpf_dbg_printk(
                "Found Go HTTP invocation, resetting the span id to %x%x", tcp->seq, tcp->ack);
            populate_span_id_from_tcp_info(&invocation->tp, tcp);
        }
    }
}

static __always_inline void encode_data_in_ip_options(struct __sk_buff *skb,
                                                      connection_info_t *conn,
                                                      protocol_info_t *tcp,
                                                      tp_info_pid_t *tp,
                                                      const egress_key_t *e_key) {
    // Handling IPv4
    // We only do this if the IP header doesn't have any options, this can be improved if needed
    if (tcp->h_proto == ETH_P_IP && tcp->ip_len == MIN_IP_LEN) {
        bpf_dbg_printk("Adding the trace_id in the IP Options");

        inject_tc_ip_options_ipv4(skb, conn, tcp, tp);
        tp->valid = 0;
    } else if (tcp->h_proto == ETH_P_IPV6 && tcp->l4_proto == IPPROTO_TCP) { // Handling IPv6
        bpf_dbg_printk("Found IPv6 header");

        inject_tc_ip_options_ipv6(skb, conn, tcp, tp);
        tp->valid = 0;
    }
}

static __always_inline struct bpf_sock *lookup_sock_from_tuple(struct __sk_buff *skb,
                                                               struct bpf_sock_tuple *tuple,
                                                               enum protocol proto,
                                                               const void *data_end) {
    if (proto == protocol_ip4 && (u64)((u8 *)tuple + sizeof(tuple->ipv4)) < (u64)data_end) {
        // Lookup to see if you can find a socket for this tuple in the
        // kernel socket tracking. We look up in all namespaces (-1).
        return bpf_sk_lookup_tcp(skb, tuple, sizeof(tuple->ipv4), BPF_F_CURRENT_NETNS, 0);
    } else if (proto == protocol_ip6 && (u64)((u8 *)tuple + sizeof(tuple->ipv6)) < (u64)data_end) {
        return bpf_sk_lookup_tcp(skb, tuple, sizeof(tuple->ipv6), BPF_F_CURRENT_NETNS, 0);
    }

    return 0;
}

// We use this helper to read in the connection tuple information in the
// bpf_sock_tuple format. We use this struct to add sockets which are
// established before we launched Beyla, since we'll not see them in the
// sock_ops program which tracks them.
static __always_inline struct bpf_sock_tuple *get_tuple(const void *data,
                                                        __u64 nh_off,
                                                        const void *data_end,
                                                        __u16 eth_proto,
                                                        enum protocol *ip_proto) {
    struct bpf_sock_tuple *result;
    __u64 ihl_len = 0;
    __u8 proto = 0;

    *ip_proto = protocol_unknown;

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(data + nh_off);

        if ((void *)(iph + 1) > data_end) {
            return 0;
        }

        ihl_len = iph->ihl * 4;
        proto = iph->protocol;
        *ip_proto = protocol_ip4;
        result = (struct bpf_sock_tuple *)&iph->saddr;
    } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + nh_off);

        if ((void *)(ip6h + 1) > data_end) {
            return 0;
        }

        ihl_len = sizeof(*ip6h);
        proto = ip6h->nexthdr;
        *ip_proto = protocol_ip6;
        result = (struct bpf_sock_tuple *)&ip6h->saddr;
    }

    if (data + nh_off + ihl_len > data_end || proto != IPPROTO_TCP) {
        return 0;
    }

    return result;
}

static __always_inline u8 is_sock_tracked(const connection_info_t *conn) {
    struct bpf_sock *sk = (struct bpf_sock *)bpf_map_lookup_elem(&sock_dir, conn);

    if (sk) {
        bpf_sk_release(sk);
        return 1;
    }

    return 0;
}

static __always_inline void track_sock(struct __sk_buff *skb, const connection_info_t *conn) {
    if (is_sock_tracked(conn)) {
        return;
    }

    // TODO revist to avoid pulling data (use bpf_skb_load_bytes instead)
    bpf_skb_pull_data(skb, skb->len);

    const void *data_end = ctx_data_end(skb);
    const void *data = ctx_data(skb);
    const struct ethhdr *eth = (struct ethhdr *)(data);

    if ((void *)(eth + 1) > data_end) {
        bpf_dbg_printk("bad size");
        return;
    }

    // Get the bpf_sock_tuple value so we can look up and see if we don't have
    // this socket yet in our map.
    enum protocol proto;
    struct bpf_sock_tuple *tuple = get_tuple(data, sizeof(*eth), data_end, eth->h_proto, &proto);
    //bpf_printk("tuple %llx, next %llx, data end %llx", tuple, (void *)((u8 *)tuple + sizeof(*tuple)), data_end);

    if (!tuple) {
        bpf_dbg_printk("bad tuple %llx, next %llx, data end %llx",
                       tuple,
                       (void *)(tuple + sizeof(struct bpf_sock_tuple)),
                       data_end);
        return;
    }

    struct bpf_sock *sk = lookup_sock_from_tuple(skb, tuple, proto, data_end);
    bpf_dbg_printk("sk=%llx\n", sk);

    if (!sk) {
        return;
    }

    bpf_map_update_elem(&sock_dir, conn, sk, BPF_NOEXIST);

    bpf_sk_release(sk);
}

SEC("tc_egress")
int beyla_app_egress(struct __sk_buff *skb) {
    //bpf_printk("egress");
    protocol_info_t tcp = {};
    connection_info_t conn = {};
    pid_connection_info_t p_conn = {};

    if (!read_sk_buff(skb, &tcp, &conn)) {
        return TC_ACT_UNSPEC;
    }

    __builtin_memcpy(&p_conn.conn, &conn, sizeof(connection_info_t));
    sort_connection_info(&p_conn.conn);

    const egress_key_t e_key = {
        .d_port = conn.d_port,
        .s_port = conn.s_port,
    };

    tp_info_pid_t *tp = bpf_map_lookup_elem(&outgoing_trace_map, &e_key);

    if (!tp) {
        return TC_ACT_UNSPEC;
    }

    // this shouldn't ever be reached, as the tp should have already been
    // deleted by the kprobes when tp->written == 1, but it does not hurt to
    // be robust
    if (tp->written) {
        bpf_dbg_printk("tp already written by L7, not injecting IP options");
        bpf_map_delete_elem(&outgoing_trace_map, &e_key);
        return TC_ACT_UNSPEC;
    }

    // We look up metadata setup by the Go uprobes or the kprobes on
    // a transaction we consider outgoing HTTP request. We will extend this in
    // the future for other protocols, e.g. gRPC/HTTP2.
    // The metadata always comes setup with the state field valid = 1, which
    // means we haven't seen this request yet.

    p_conn.pid = tp->pid;
    bpf_dbg_printk("egress flags %x, sequence %x, valid %d", tcp.flags, tcp.seq, tp->valid);
    dbg_print_http_connection_info(&conn);

    // If it's the fist packet of an request:
    // We set the span information to match our TCP information. This
    // is done for L4 context propagation, where we use the SEQ/ACK
    // numbers for the Span ID. Since this is the first time we see
    // these SEQ,ACK ids, we update the random Span ID the metadata has
    // to match what we send over the wire.
    if (tp->valid == 1) {
        populate_span_id_from_tcp_info(&tp->tp, &tcp);
        update_outgoing_request_span_id(&p_conn, &tcp, tp, &e_key);
        // We set valid to 2, so we only run this once, the later packets
        // will have different SEQ/ACK.
        tp->valid = 2;
    }

    // track any sockets we may have missed from sockops
    track_sock(skb, &conn);

    // The following code sets up the context information in L4 and it
    // does it only once. If it successfully injected the information it
    // will set valid to 0 so that we only run the L7 part from now on.
    if (tp->valid) {
        encode_data_in_ip_options(skb, &conn, &tcp, tp, &e_key);
    }

    return TC_ACT_UNSPEC;
}
