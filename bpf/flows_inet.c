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

#include "vmlinux.h"

#include "bpf_core_read.h"

#include "flows_common.h"
#include "http_defs.h"

struct birth {
    __u64 ts;		// timestamp of first packet
    bool initiator;	// am i the initiator?
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 24);
	__type(key, struct sock *);
	__type(value, struct birth);
} births SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *args)
{
    int new_state;
    flow_id id; 
    struct sock *sk;
    struct tcp_sock *tp;
    struct birth start = {}, *startp;
    u64 ts, rx_b, tx_b;

    new_state = BPF_CORE_READ(args, newstate);

    //interested in TCP_SYN_SENT, TCP_SYN_RECV and TCP_CLOSE only
	if (new_state != TCP_SYN_SENT && new_state != TCP_SYN_RECV && new_state != TCP_CLOSE)
		return 0;

    sk = (struct sock *)BPF_CORE_READ(args, skaddr);

	if (new_state == TCP_SYN_SENT || new_state == TCP_SYN_RECV) {

		//start connection timestamp
		ts = bpf_ktime_get_ns();
		start.ts = ts;

		//am I the initiator of the connection
		start.initiator = new_state == TCP_SYN_SENT;

		//store in map births, sk sock struct (network layer representation of sockets) as a key
		bpf_map_update_elem(&births, &sk, &start, BPF_ANY);
		return 0;
	} else if (new_state == TCP_CLOSE) {

        //get element from births map for that sock struct
		startp = bpf_map_lookup_elem(&births, &sk);
		if (!startp) {
			return 0;
		}

        id.eth_protocol = BPF_CORE_READ(args, family);
        id.transport_protocol = BPF_CORE_READ(args, protocol);
        __builtin_memcpy(id.src_ip.s6_addr, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(id.dst_ip.s6_addr, ip4in6, sizeof(ip4in6));
        
        if(startp->initiator) {
            id.direction = EGRESS;
            bpf_probe_read_kernel(id.src_ip.s6_addr + sizeof(ip4in6), sizeof(args->saddr), BPF_CORE_READ(args, saddr));
            bpf_probe_read_kernel(id.dst_ip.s6_addr + sizeof(ip4in6), sizeof(args->daddr), BPF_CORE_READ(args, daddr));
            id.src_port = BPF_CORE_READ(args, sport);
            id.dst_port = BPF_CORE_READ(args, dport);
        }
        else {
            id.direction = INGRESS;
            bpf_probe_read_kernel(id.dst_ip.s6_addr + sizeof(ip4in6), sizeof(args->saddr), BPF_CORE_READ(args, saddr));
            bpf_probe_read_kernel(id.src_ip.s6_addr + sizeof(ip4in6), sizeof(args->daddr), BPF_CORE_READ(args, daddr));
            id.dst_port = BPF_CORE_READ(args, sport);
            id.src_port = BPF_CORE_READ(args, dport);
        }


        tp = (struct tcp_sock *)sk;
        rx_b = BPF_CORE_READ(tp, bytes_received);
        tx_b = BPF_CORE_READ(tp, bytes_acked);

        u64 current_time = bpf_ktime_get_ns();

        // call to bpf_map_lookup_elem on aggregated_flows removed, because it doesn't have sense regarding this approach

        flow_metrics new_flow = {
            .packets = 1,
            .bytes = rx_b + tx_b,
            .start_mono_time_ns = startp->ts,
            .end_mono_time_ns = current_time,
        };

        // even if we know that the entry is new, another CPU might be concurrently inserting a flow
        // so we need to specify BPF_ANY
        long ret = bpf_map_update_elem(&aggregated_flows, &id, &new_flow, BPF_ANY);
        if (ret != 0) {
            // usually error -16 (-EBUSY) or -7 (E2BIG) is printed here.
            // In this case, we send the single-packet flow via ringbuffer as in the worst case we can have
            // a repeated INTERSECTION of flows (different flows aggregating different packets),
            // which can be re-aggregated at userpace.
            // other possible values https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
            if (trace_messages) {
                bpf_printk("error adding flow %d\n", ret);
            }

            new_flow.errno = -ret;
            flow_record *record = (flow_record *)bpf_ringbuf_reserve(&direct_flows, sizeof(flow_record), 0);
            if (record) {
                record->id = id;
                record->metrics = new_flow;
                bpf_ringbuf_submit(record, 0);
            } else {
                if (trace_messages) {
                    bpf_printk("couldn't reserve space in the ringbuf. Dropping flow");
                }
            }
        }
        bpf_map_delete_elem(&births, &sk);
    }
    return 0;
}

// Force emitting structs into the ELF for automatic creation of Golang struct
const flow_metrics *unused_flow_metrics __attribute__((unused));
const flow_id *unused_flow_id __attribute__((unused));
const flow_record *unused_flow_record __attribute__((unused));

char __license[] SEC("license") = "Dual MIT/GPL";
