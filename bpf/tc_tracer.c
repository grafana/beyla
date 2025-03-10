//go:build beyla_bpf_ignore
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_dbg.h"

#include "http_maps.h"
#include "http_types.h"
#include "go_shared.h"
#include "tc_ip.h"
#include "tcp_info.h"
#include "tc_act.h"
#include "tc_sock.h"
#include "tc_tracer_l7.h"

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
                                                            egress_key_t *e_key) {
    http_info_t *h_info = bpf_map_lookup_elem(&ongoing_http, p_conn);
    if (h_info && tp->valid) {
        bpf_dbg_printk("Found HTTP info, resetting the span id to %x%x", tcp->seq, tcp->ack);
        populate_span_id_from_tcp_info(&h_info->tp, tcp);
    }

    go_addr_key_t *g_key = bpf_map_lookup_elem(&ongoing_go_http, e_key);
    if (g_key) {
        bpf_dbg_printk("Found Go HTTP info, trying to find the span id");
        http_func_invocation_t *invocation =
            bpf_map_lookup_elem(&ongoing_http_client_requests, g_key);
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
                                                      egress_key_t *e_key) {
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

    egress_key_t e_key = {
        .d_port = conn.d_port,
        .s_port = conn.s_port,
    };

    tp_info_pid_t *tp = bpf_map_lookup_elem(&outgoing_trace_map, &e_key);

    // We look up metadata setup by the Go uprobes or the kprobes on
    // a transaction we consider outgoing HTTP request. We will extend this in
    // the future for other protocols, e.g. gRPC/HTTP2.
    // The metadata always comes setup with the state field valid = 1, which
    // means we haven't seen this request yet.
    if (tp) {
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
        // L7 app egress runs on every packet, the packets will be split so
        // it needs to do work across all packets that go out for this request
        l7_app_egress(skb, tp, &conn, &tcp, &e_key);

        // The following code sets up the context information in L4 and it
        // does it only once. If it successfully injected the information it
        // will set valid to 0 so that we only run the L7 part from now on.
        if (tp->valid) {
            encode_data_in_ip_options(skb, &conn, &tcp, tp, &e_key);
        }
    } else {
        u32 s_port = e_key.s_port;
        tc_http_ctx_t *ctx = (tc_http_ctx_t *)bpf_map_lookup_elem(&tc_http_ctx_map, &s_port);

        if (ctx) {
            bpf_dbg_printk("No trace-map info, filling up the hole setup by sk_msg");
            bpf_skb_pull_data(skb, skb->len);
            write_traceparent(skb, &tcp, &e_key, ctx, INV_TP);
        }
    }

    return TC_ACT_UNSPEC;
}
