#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/tcp_info.h>
#include <common/tracing.h>

#include <logger/bpf_dbg.h>

enum { MIN_IP_LEN = 20, MAX_TC_TP_LEN = 20, TC_TP_ID = 0x1488, MAX_IPV6_OPTS_LEN = 24 };

static __always_inline void populate_span_id_from_tcp_info(tp_info_t *tp, protocol_info_t *tcp) {
    // We use a combination of the TCP sequence + TCP ack as a SpanID
    *((u32 *)(&tp->span_id[0])) = tcp->seq;
    *((u32 *)(&tp->span_id[4])) = tcp->ack;
}

static __always_inline void print_tp(tp_info_pid_t *new_tp) {
#ifdef BPF_DEBUG
    unsigned char tp_buf[TP_MAX_VAL_LENGTH];

    make_tp_string(tp_buf, &new_tp->tp);
    bpf_dbg_printk("tp: %s", tp_buf);
#endif
}

static __always_inline void
parse_ip_options_ipv4(struct __sk_buff *skb, connection_info_t *conn, protocol_info_t *tcp) {
    u16 key = 0;
    int ip_off = MIN_IP_LEN + ETH_HLEN;

    dbg_print_http_connection_info(conn);

    sort_connection_info(conn);
    bpf_skb_load_bytes(skb, ip_off, &key, sizeof(key));
    bpf_dbg_printk("options %llx, len = %d", key, tcp->ip_len);
    if (key == TC_TP_ID) {
        tp_info_pid_t *existing_tp =
            (tp_info_pid_t *)bpf_map_lookup_elem(&incoming_trace_map, conn);
        if (!existing_tp) {
            bpf_dbg_printk("Found tp context in opts! ihl = %d", tcp->ip_len);
            tp_info_pid_t new_tp = {.pid = 0, .valid = 1};
            populate_span_id_from_tcp_info(&new_tp.tp, tcp);

            // We load the TraceID from the IP options field. We skip two bytes for the key 0x88 + len (2 bytes)
            bpf_skb_load_bytes(
                skb, ip_off + sizeof(key), &new_tp.tp.trace_id[0], sizeof(new_tp.tp.trace_id));

            print_tp(&new_tp);

            bpf_map_update_elem(&incoming_trace_map, conn, &new_tp, BPF_ANY);
        } else {
            bpf_dbg_printk("ignoring existing tp");
        }
    }
}

static __always_inline void
parse_ip_options_ipv6(struct __sk_buff *skb, connection_info_t *conn, protocol_info_t *tcp) {
    bpf_dbg_printk("IPv6 ingress");
    dbg_print_http_connection_info(conn);

    sort_connection_info(conn);
    tp_info_pid_t *existing_tp = (tp_info_pid_t *)bpf_map_lookup_elem(&incoming_trace_map, conn);
    if (!existing_tp) {
        tp_info_pid_t new_tp = {.pid = 0, .valid = 1};
        populate_span_id_from_tcp_info(&new_tp.tp, tcp);

        // Skip the first 4 bytes (next header, len, dest option, dest len)
        int ip_off = tcp->ip_len + 4;
        // We load the TraceID from the IP options field. We skip two bytes for the key 0x88 + len (2 bytes)
        bpf_skb_load_bytes(skb, ip_off, &new_tp.tp.trace_id[0], sizeof(new_tp.tp.trace_id));

        print_tp(&new_tp);
        bpf_map_update_elem(&incoming_trace_map, conn, &new_tp, BPF_ANY);
    }
}

static __always_inline u8 inject_tc_ip_options_ipv4(struct __sk_buff *skb,
                                                    connection_info_t *conn,
                                                    protocol_info_t *tcp,
                                                    tp_info_pid_t *tp) {
    if (!bpf_skb_adjust_room(skb, MAX_TC_TP_LEN, BPF_ADJ_ROOM_NET, BPF_F_ADJ_ROOM_NO_CSUM_RESET)) {
        u16 zero = 0;
        // Stream_id, 20 bytes length. The length value must be a multiple of 4, so we need 20 bytes total.
        // The length includes the TC_TP_ID, 2 bytes (TC_TP_ID) + 16 bytes (TraceID) + 2 bytes zeroes = 20 bytes.
        u16 key = TC_TP_ID;
        int ip_off = tcp->ip_len + ETH_HLEN;
        bpf_skb_store_bytes(skb, ip_off, &key, sizeof(key), 0);
        bpf_skb_store_bytes(
            skb, ip_off + sizeof(key), &tp->tp.trace_id[0], sizeof(tp->tp.trace_id), 0);
        bpf_skb_store_bytes(
            skb, ip_off + sizeof(key) + sizeof(tp->tp.trace_id), &zero, sizeof(zero), 0);
        u8 offset_ip_tot_len = ETH_HLEN + offsetof(struct iphdr, tot_len);

        u16 new_tot_len = bpf_htons(bpf_ntohs(tcp->tot_len) + MAX_TC_TP_LEN);

        u8 hdr_len; // this 1 byte field is a composite of the IP version and the IHL
        bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));

        u8 hdr_ver = hdr_len;
        u8 new_hdr_len = hdr_len;
        new_hdr_len &= 0x0f;
        new_hdr_len += (MAX_TC_TP_LEN / 4); // IHL is a number of 32bit words
        new_hdr_len |= hdr_ver & 0xf0;

        bpf_dbg_printk(
            "prev h_len %d, new_h_len %d, new_tot_len %d", hdr_len, new_hdr_len, new_tot_len);

        bpf_skb_store_bytes(skb, offset_ip_tot_len, &new_tot_len, sizeof(u16), 0);
        bpf_skb_store_bytes(skb, ETH_HLEN, &new_hdr_len, sizeof(u8), 0);

        u32 offset_ip_checksum = ETH_HLEN + offsetof(struct iphdr, check);

        // Update the IPv4 checksum for the change of the total packet length
        bpf_l3_csum_replace(skb, offset_ip_checksum, tcp->tot_len, new_tot_len, sizeof(u16));
        // Update the IPv4 checksum for the change of the IHL IP header field. We use replace of 2 bytes because
        // it's the minimum the API can do.
        bpf_l3_csum_replace(skb, offset_ip_checksum, hdr_len, new_hdr_len, sizeof(u16));
        // Update the IPv4 checksum for the addition of the ID magic number 0x88 + length (20)
        bpf_l3_csum_replace(skb, offset_ip_checksum, 0, TC_TP_ID, sizeof(u16));
        // Update the IPv4 checksum for the TraceID value. The l3_csum_replace can only replace 2 or 4 byte values
        for (int i = 0; i < 4; i++) {
            bpf_l3_csum_replace(skb,
                                offset_ip_checksum,
                                0,
                                *((u32 *)&tp->tp.trace_id[i * sizeof(u32)]),
                                sizeof(u32));
        }

        return 1;
    }

    return 0;
}

static __always_inline u8 inject_tc_ip_options_ipv6(struct __sk_buff *skb,
                                                    connection_info_t *conn,
                                                    protocol_info_t *tcp,
                                                    tp_info_pid_t *tp) {
    if (!bpf_skb_adjust_room(skb,
                             MAX_IPV6_OPTS_LEN,
                             BPF_ADJ_ROOM_NET,
                             BPF_F_ADJ_ROOM_NO_CSUM_RESET)) { // Must be 8 byte aligned size
        u8 next_hdr = IP_V6_DEST_OPTS;                        // 60 -> Destination options
        int next_hdr_off = ETH_HLEN + offsetof(struct ipv6hdr, nexthdr);
        bpf_skb_store_bytes(skb, next_hdr_off, &next_hdr, sizeof(next_hdr), 0);

        int next_hdr_start = tcp->ip_len;
        bpf_skb_store_bytes(skb,
                            next_hdr_start,
                            &tcp->l4_proto,
                            sizeof(tcp->l4_proto),
                            0); // The next header now has the L4 protocol info

        u8 offset_ip_tot_len = ETH_HLEN + offsetof(struct ipv6hdr, payload_len);
        u16 new_tot_len = bpf_htons(bpf_ntohs(tcp->tot_len) + MAX_IPV6_OPTS_LEN);
        bpf_skb_store_bytes(skb, offset_ip_tot_len, &new_tot_len, sizeof(u16), 0);

        u8 hdr_len = (MAX_IPV6_OPTS_LEN - 8) / 8; // this value is expressed as multiples of 8
        bpf_skb_store_bytes(skb,
                            next_hdr_start + sizeof(next_hdr),
                            &hdr_len,
                            sizeof(hdr_len),
                            0); // The next header length is the total size - the first 8 bytes

        // 09 - Unknown option (thought about PadN but Linux kernel doesn't like it), 14 = 20 bytes length total padding
        u16 options = 0x1409;
        // https://github.com/torvalds/linux/blob/87d6aab2389e5ce0197d8257d5f8ee965a67c4cd/net/ipv6/exthdrs.c#L150
        bpf_skb_store_bytes(skb,
                            next_hdr_start + sizeof(next_hdr) + sizeof(hdr_len),
                            &options,
                            sizeof(options),
                            0); // The next header length is the total size - the first 8 bytes

        bpf_skb_store_bytes(skb,
                            next_hdr_start + sizeof(next_hdr) + sizeof(hdr_len) + sizeof(options),
                            &tp->tp.trace_id[0],
                            sizeof(tp->tp.trace_id),
                            0);

        return 1;
    }

    return 0;
}
