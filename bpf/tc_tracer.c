#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_dbg.h"

#include "http_maps.h"
#include "http_types.h"
#include "go_shared.h"
#include "tc_ip.h"
#include "tcp_info.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("tc_ingress")
int app_ingress(struct __sk_buff *skb) {
    //bpf_printk("ingress");

    protocol_info_t tcp = {};
    connection_info_t conn = {};

    if (!read_sk_buff(skb, &tcp, &conn)) {
        return 0;
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

    return 0;
}

static __always_inline void update_outgoing_request_span_id(connection_info_t *conn,
                                                            protocol_info_t *tcp,
                                                            tp_info_pid_t *tp,
                                                            egress_key_t *e_key) {
    http_info_t *h_info = bpf_map_lookup_elem(&ongoing_http, e_key);
    if (h_info && tp->valid) {
        bpf_dbg_printk("Found HTTP info, resetting the span id to %x%x", tcp->seq, tcp->ack);
        *((u32 *)(&h_info->tp.span_id[0])) = tcp->seq;
        *((u32 *)(&h_info->tp.span_id[4])) = tcp->ack;
    }

    go_addr_key_t *g_key = bpf_map_lookup_elem(&ongoing_go_http, e_key);
    if (g_key) {
        bpf_dbg_printk("Found Go HTTP info, trying to find the span id");
        http_func_invocation_t *invocation =
            bpf_map_lookup_elem(&ongoing_http_client_requests, g_key);
        if (invocation) {
            bpf_dbg_printk(
                "Found Go HTTP invocation, resetting the span id to %x%x", tcp->seq, tcp->ack);

            *((u32 *)(&invocation->tp.span_id[0])) = tcp->seq;
            *((u32 *)(&invocation->tp.span_id[4])) = tcp->ack;
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

        if (inject_tc_ip_options_ipv4(skb, conn, tcp, tp)) {
            update_outgoing_request_span_id(conn, tcp, tp, e_key);
        }

        bpf_map_delete_elem(&outgoing_trace_map, e_key);
    } else if (tcp->h_proto == ETH_P_IPV6 && tcp->l4_proto == IPPROTO_TCP) { // Handling IPv6
        bpf_dbg_printk("Found IPv6 header");

        if (inject_tc_ip_options_ipv6(skb, conn, tcp, tp)) {
            update_outgoing_request_span_id(conn, tcp, tp, e_key);
        }

        bpf_map_delete_elem(&outgoing_trace_map, e_key);
    }
}

SEC("tc_egress")
int app_egress(struct __sk_buff *skb) {
    //bpf_printk("egress");

    protocol_info_t tcp = {};
    connection_info_t conn = {};

    if (!read_sk_buff(skb, &tcp, &conn)) {
        return 0;
    }

    sort_connection_info(&conn);
    egress_key_t e_key = {
        .d_port = conn.d_port,
        .s_port = conn.s_port,
    };

    tp_info_pid_t *tp = bpf_map_lookup_elem(&outgoing_trace_map, &e_key);

    if (tp) {
        bpf_dbg_printk("egress flags %x, sequence %x", tcp.flags, tcp.seq);
        dbg_print_http_connection_info(&conn);

        encode_data_in_ip_options(skb, &conn, &tcp, tp, &e_key);
    }

    return 0;
}
