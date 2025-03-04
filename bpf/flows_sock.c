//go:build beyla_bpf_ignore
// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

#include "vmlinux.h"
#include <stdbool.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf_dbg.h"
#include "flows_common.h"
#include "protocol_defs.h"

struct __tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
    __u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1,
        cwr : 1;
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
};

struct __udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
};

static __always_inline bool read_sk_buff(struct __sk_buff *skb, flow_id *id, u16 *custom_flags) {
    // we read the protocol just like here linux/samples/bpf/parse_ldabs.c
    u16 h_proto;
    bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto, sizeof(h_proto));
    h_proto = __bpf_htons(h_proto);
    id->eth_protocol = h_proto;

    u8 hdr_len;
    u8 proto = 0;
    // do something similar as linux/samples/bpf/parse_varlen.c
    switch (h_proto) {
    case ETH_P_IP: {
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

        __builtin_memcpy(id->src_ip.s6_addr, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(id->dst_ip.s6_addr, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(id->src_ip.s6_addr + sizeof(ip4in6), &saddr, sizeof(saddr));
        __builtin_memcpy(id->dst_ip.s6_addr + sizeof(ip4in6), &daddr, sizeof(daddr));

        hdr_len = ETH_HLEN + hdr_len;
        break;
    }
    case ETH_P_IPV6:
        bpf_skb_load_bytes(
            skb, ETH_HLEN + offsetof(struct ipv6hdr, nexthdr), &proto, sizeof(proto));

        bpf_skb_load_bytes(skb,
                           ETH_HLEN + offsetof(struct ipv6hdr, saddr),
                           &id->src_ip.s6_addr,
                           sizeof(id->src_ip.s6_addr));
        bpf_skb_load_bytes(skb,
                           ETH_HLEN + offsetof(struct ipv6hdr, daddr),
                           &id->dst_ip.s6_addr,
                           sizeof(id->dst_ip.s6_addr));

        hdr_len = ETH_HLEN + sizeof(struct ipv6hdr);
        break;
    default:
        return false;
    }

    id->src_port = 0;
    id->dst_port = 0;
    id->transport_protocol = proto;

    switch (proto) {
    case IPPROTO_TCP: {
        u16 port;
        bpf_skb_load_bytes(skb, hdr_len + offsetof(struct __tcphdr, source), &port, sizeof(port));
        id->src_port = __bpf_htons(port);

        bpf_skb_load_bytes(skb, hdr_len + offsetof(struct __tcphdr, dest), &port, sizeof(port));
        id->dst_port = __bpf_htons(port);

        u8 doff;
        bpf_skb_load_bytes(
            skb,
            hdr_len + offsetof(struct __tcphdr, ack_seq) + 4,
            &doff,
            sizeof(
                doff)); // read the first byte past __tcphdr->ack_seq, we can't do offsetof bit fields
        doff &= 0xf0;   // clean-up res1
        doff >>= 4;     // move the upper 4 bits to low
        doff *= 4;      // convert to bytes length

        u8 flags;
        bpf_skb_load_bytes(
            skb,
            hdr_len + offsetof(struct __tcphdr, ack_seq) + 4 + 1,
            &flags,
            sizeof(flags)); // read the second byte past __tcphdr->doff, again bit fields offsets
        *custom_flags = ((u16)flags & 0x00ff);

        hdr_len += doff;

        if ((skb->len - hdr_len) < 0) { // less than 0 is a packet we can't parse
            return false;
        }

        break;
    }
    case IPPROTO_UDP: {
        u16 port;
        bpf_skb_load_bytes(skb, hdr_len + offsetof(struct __udphdr, source), &port, sizeof(port));
        id->src_port = __bpf_htons(port);
        bpf_skb_load_bytes(skb, hdr_len + offsetof(struct __udphdr, dest), &port, sizeof(port));
        id->dst_port = __bpf_htons(port);
        break;
    }
    default:
        return false;
    }

    // custom flags
    if ((*custom_flags & (TCPHDR_ACK | TCPHDR_SYN))) {
        *custom_flags |= SYN_ACK_FLAG;
    } else if ((*custom_flags & (TCPHDR_ACK | TCPHDR_FIN))) {
        *custom_flags |= FIN_ACK_FLAG;
    } else if ((*custom_flags & (TCPHDR_ACK | TCPHDR_RST))) {
        *custom_flags |= RST_ACK_FLAG;
    }

    return true;
}

static __always_inline bool same_ip(const u8 *ip1, const u8 *ip2) {
    for (int i = 0; i < 16; i += 4) {
        if (*((u32 *)(ip1 + i)) != *((u32 *)(ip2 + i))) {
            return false;
        }
    }

    return true;
}

SEC("socket/http_filter")
int beyla_socket__http_filter(struct __sk_buff *skb) {
    // If sampling is defined, will only parse 1 out of "sampling" flows
    if (sampling != 0 && (bpf_get_prandom_u32() % sampling) != 0) {
        return TC_ACT_UNSPEC;
    }

    u16 flags = 0;
    flow_id id;
    __builtin_memset(&id, 0, sizeof(id));
    if (!read_sk_buff(skb, &id, &flags)) {
        return TC_ACT_UNSPEC;
    }

    // ignore traffic that's not egress or ingress
    if (same_ip(id.src_ip.s6_addr, id.dst_ip.s6_addr)) {
        return TC_ACT_UNSPEC;
    }

    u64 current_time = bpf_ktime_get_ns();

    // TODO: we need to add spinlock here when we deprecate versions prior to 5.1, or provide
    // a spinlocked alternative version and use it selectively https://lwn.net/Articles/779120/
    flow_metrics *aggregate_flow = (flow_metrics *)bpf_map_lookup_elem(&aggregated_flows, &id);
    if (aggregate_flow != NULL) {
        aggregate_flow->packets += 1;
        aggregate_flow->bytes += skb->len;
        aggregate_flow->end_mono_time_ns = current_time;
        // it might happen that start_mono_time hasn't been set due to
        // the way percpu hashmap deal with concurrent map entries
        if (aggregate_flow->start_mono_time_ns == 0) {
            aggregate_flow->start_mono_time_ns = current_time;
        }
        aggregate_flow->flags |= flags;

        long ret = bpf_map_update_elem(&aggregated_flows, &id, aggregate_flow, BPF_ANY);
        if (trace_messages && ret != 0) {
            // usually error -16 (-EBUSY) is printed here.
            // In this case, the flow is dropped, as submitting it to the ringbuffer would cause
            // a duplicated UNION of flows (two different flows with partial aggregation of the same packets),
            // which can't be deduplicated.
            // other possible values https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
            bpf_dbg_printk("error updating flow %d\n", ret);
        }
    } else {
        // Key does not exist in the map, and will need to create a new entry.
        flow_metrics new_flow = {
            .packets = 1,
            .bytes = skb->len,
            .start_mono_time_ns = current_time,
            .end_mono_time_ns = current_time,
            .flags = flags,
            .iface_direction = UNKNOWN,
        };

        u8 *direction = (u8 *)bpf_map_lookup_elem(&flow_directions, &id);
        if (direction == NULL) {
            // Calculate direction based on first flag received
            // SYN and ACK mean someone else initiated the connection and this is the INGRESS direction
            if ((flags & (SYN_FLAG | ACK_FLAG)) == (SYN_FLAG | ACK_FLAG)) {
                new_flow.iface_direction = INGRESS;
            }
            // SYN only means we initiated the connection and this is the EGRESS direction
            else if ((flags & SYN_FLAG) == SYN_FLAG) {
                new_flow.iface_direction = EGRESS;
            }
            // save, when direction was calculated based on TCP flag
            if (new_flow.iface_direction != UNKNOWN) {
                // errors are intentionally omitted
                bpf_map_update_elem(&flow_directions, &id, &new_flow.iface_direction, BPF_NOEXIST);
            }
            // fallback for lost or already started connections and UDP
            else {
                new_flow.iface_direction = INGRESS;
                if (id.src_port > id.dst_port) {
                    new_flow.iface_direction = EGRESS;
                }
            }
        } else {
            // get direction from saved flow
            new_flow.iface_direction = *direction;
        }

        new_flow.initiator = get_connection_initiator(&id, flags);

        // even if we know that the entry is new, another CPU might be concurrently inserting a flow
        // so we need to specify BPF_ANY
        long ret = bpf_map_update_elem(&aggregated_flows, &id, &new_flow, BPF_ANY);
        if (ret != 0) {
            // usually error -16 (-EBUSY) or -7 (E2BIG) is printed here.
            // In this case, we send the single-packet flow via ringbuffer as in the worst case we can have
            // a repeated INTERSECTION of flows (different flows aggregating different packets),
            // which can be re-aggregated at userspace.
            // other possible values https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
            if (trace_messages) {
                bpf_dbg_printk("error adding flow %d\n", ret);
            }

            new_flow.errno = -ret;
            flow_record *record =
                (flow_record *)bpf_ringbuf_reserve(&direct_flows, sizeof(flow_record), 0);
            if (!record) {
                if (trace_messages) {
                    bpf_dbg_printk("couldn't reserve space in the ringbuf. Dropping flow");
                }
                goto cleanup;
            }
            record->id = id;
            record->metrics = new_flow;
            bpf_ringbuf_submit(record, 0);
        }
    }

cleanup:
    // finally, when flow receives FIN or RST, clean flow_directions
    if (flags & FIN_FLAG || flags & RST_FLAG) {
        bpf_map_delete_elem(&flow_directions, &id);
    }
    return TC_ACT_UNSPEC;
}

// Force emitting structs into the ELF for automatic creation of Golang struct
const flow_metrics *unused_flow_metrics __attribute__((unused));
const flow_id *unused_flow_id __attribute__((unused));
const flow_record *unused_flow_record __attribute__((unused));

char _license[] SEC("license") = "GPL";
