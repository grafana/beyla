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

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/tc_act.h>

#define IP_MAX_LEN 16

#define ETH_ALEN 6 /* Octets in one ethernet addr   */

#define s6_addr in6_u.u6_addr8
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/
// ETH_P_IPV6 value as defined in IEEE 802: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/
typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

typedef struct flow_metrics_t {
    u64 bytes;
    // start_mono_time_ts and end_mono_time_ts are the start and end times as system monotonic timestamps
    // in nanoseconds, as output from bpf_ktime_get_ns() (kernel space)
    // and monotime.Now() (user space)
    u64 start_mono_time_ns;
    u64 end_mono_time_ns;

    u32 packets;

    // TCP Flags from https://www.ietf.org/rfc/rfc793.txt
    u16 flags;
    // direction of the flow EGRESS / INGRESS
    u8 iface_direction;
    // who initiated of the connection: INITIATOR_SRC or INITIATOR_DST
    u8 initiator;
    // The positive errno of a failed map insertion that caused a flow
    // to be sent via ringbuffer.
    // 0 otherwise
    // https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
    u8 errno;

    u8 _pad[7];
} flow_metrics;

// Attributes that uniquely identify a flow
// TODO: remove attributes that won't be used in Beyla (e.g. MAC, maybe protocol...)
typedef struct flow_id_t {
    // L3 network layer
    // IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
    // as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
    struct in6_addr src_ip; // keep these aligned
    struct in6_addr dst_ip;
    // OS interface index
    u32 if_index;

    u16 eth_protocol;

    // L4 transport layer
    u16 src_port;
    u16 dst_port;
    u8 transport_protocol;
    u8 _pad[1];
} flow_id;

// Flow record is a tuple containing both flow identifier and metrics. It is used to send
// a complete flow via ring buffer when only when the accounting hashmap is full.
// Contents in this struct must match byte-by-byte with Go's pkc/flow/Record struct
typedef struct flow_record_t {
    flow_metrics metrics;
    flow_id id;
    u8 _pad[4];
} flow_record;
