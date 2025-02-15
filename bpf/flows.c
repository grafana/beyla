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

// sets the TCP header flags for connection information
static inline void set_flags(struct tcphdr *th, u16 *flags) {
    //If both ACK and SYN are set, then it is server -> client communication during 3-way handshake.
    if (th->ack && th->syn) {
        *flags |= SYN_ACK_FLAG;
    } else if (th->ack && th->fin) {
        // If both ACK and FIN are set, then it is graceful termination from server.
        *flags |= FIN_ACK_FLAG;
    } else if (th->ack && th->rst) {
        // If both ACK and RST are set, then it is abrupt connection termination.
        *flags |= RST_ACK_FLAG;
    } else if (th->fin) {
        *flags |= FIN_FLAG;
    } else if (th->syn) {
        *flags |= SYN_FLAG;
    } else if (th->rst) {
        *flags |= RST_FLAG;
    } else if (th->psh) {
        *flags |= PSH_FLAG;
    } else if (th->urg) {
        *flags |= URG_FLAG;
    } else if (th->ece) {
        *flags |= ECE_FLAG;
    } else if (th->cwr) {
        *flags |= CWR_FLAG;
    }
}
// sets flow fields from IPv4 header information
static inline int fill_iphdr(struct iphdr *ip, void *data_end, flow_id *id, u16 *flags) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }

    __builtin_memcpy(id->src_ip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->dst_ip.s6_addr, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->src_ip.s6_addr + sizeof(ip4in6), &ip->saddr, sizeof(ip->saddr));
    __builtin_memcpy(id->dst_ip.s6_addr + sizeof(ip4in6), &ip->daddr, sizeof(ip->daddr));
    id->transport_protocol = ip->protocol;
    id->src_port = 0;
    id->dst_port = 0;
    switch (ip->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + sizeof(*ip));
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            id->src_port = __bpf_ntohs(tcp->source);
            id->dst_port = __bpf_ntohs(tcp->dest);
            set_flags(tcp, flags);
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = (struct udphdr *)((void *)ip + sizeof(*ip));
        if ((void *)udp + sizeof(*udp) <= data_end) {
            id->src_port = __bpf_ntohs(udp->source);
            id->dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    default:
        break;
    }
    return SUBMIT;
}

// sets flow fields from IPv6 header information
static inline int fill_ip6hdr(struct ipv6hdr *ip, void *data_end, flow_id *id, u16 *flags) {
    if ((void *)ip + sizeof(*ip) > data_end) {
        return DISCARD;
    }

    id->src_ip = ip->saddr;
    id->dst_ip = ip->daddr;
    id->transport_protocol = ip->nexthdr;
    id->src_port = 0;
    id->dst_port = 0;
    switch (ip->nexthdr) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (struct tcphdr *)((void *)ip + sizeof(*ip));
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            id->src_port = __bpf_ntohs(tcp->source);
            id->dst_port = __bpf_ntohs(tcp->dest);
            set_flags(tcp, flags);
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = (struct udphdr *)((void *)ip + sizeof(*ip));
        if ((void *)udp + sizeof(*udp) <= data_end) {
            id->src_port = __bpf_ntohs(udp->source);
            id->dst_port = __bpf_ntohs(udp->dest);
        }
    } break;
    default:
        break;
    }
    return SUBMIT;
}
// sets flow fields from Ethernet header information
static inline int fill_ethhdr(struct ethhdr *eth, void *data_end, flow_id *id, u16 *flags) {
    if ((void *)eth + sizeof(*eth) > data_end) {
        return DISCARD;
    }

    id->eth_protocol = __bpf_ntohs(eth->h_proto);

    if (id->eth_protocol == ETH_P_IP) {
        struct iphdr *ip = (struct iphdr *)((void *)eth + sizeof(*eth));
        return fill_iphdr(ip, data_end, id, flags);
    } else if (id->eth_protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (struct ipv6hdr *)((void *)eth + sizeof(*eth));
        return fill_ip6hdr(ip6, data_end, id, flags);
    } else {
        // TODO : Need to implement other specific ethertypes if needed
        // For now other parts of flow id remain zero
        __builtin_memset(&(id->src_ip), 0, sizeof(struct in6_addr));
        __builtin_memset(&(id->dst_ip), 0, sizeof(struct in6_addr));
        id->transport_protocol = 0;
        id->src_port = 0;
        id->dst_port = 0;
    }
    return SUBMIT;
}

static inline int flow_monitor(struct __sk_buff *skb) {
    // If sampling is defined, will only parse 1 out of "sampling" flows
    if (sampling != 0 && (bpf_get_prandom_u32() % sampling) != 0) {
        return TC_ACT_UNSPEC;
    }
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    flow_id id;
    __builtin_memset(&id, 0, sizeof(id));
    struct ethhdr *eth = (struct ethhdr *)data;
    u16 flags = 0;
    if (fill_ethhdr(eth, data_end, &id, &flags) == DISCARD) {
        return TC_ACT_UNSPEC;
    }
    id.if_index = skb->ifindex;

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
            .initiator = INITIATOR_UNKNOWN,
        };

        u8 *direction = (u8 *)bpf_map_lookup_elem(&flow_directions, &id);
        if (direction == NULL) {
            // Calculate direction based on first flag received
            // SYN and ACK mean someone else initiated the connection and this is the INGRESS direction
            if ((flags & SYN_ACK_FLAG) == SYN_ACK_FLAG) {
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
    if (flags & FIN_FLAG || flags & RST_FLAG || flags & FIN_ACK_FLAG || flags & RST_ACK_FLAG) {
        bpf_map_delete_elem(&flow_directions, &id);
    }
    return TC_ACT_UNSPEC;
}

SEC("tc_ingress")
int beyla_ingress_flow_parse(struct __sk_buff *skb) {
    return flow_monitor(skb);
}

SEC("tc_egress")
int beyla_egress_flow_parse(struct __sk_buff *skb) {
    return flow_monitor(skb);
}

// Force emitting structs into the ELF for automatic creation of Golang struct
const flow_metrics *unused_flow_metrics __attribute__((unused));
const flow_id *unused_flow_id __attribute__((unused));
const flow_record *unused_flow_record __attribute__((unused));

char _license[] SEC("license") = "GPL";
