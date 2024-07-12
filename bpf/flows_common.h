#ifndef __FLOW_HELPERS_H__
#define __FLOW_HELPERS_H__

#include "vmlinux.h"
#include <stdbool.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

#include "flow.h"

#define DISCARD 1
#define SUBMIT 0

// according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define INGRESS 0
#define EGRESS 1
#define UNKNOWN 255

// Flags according to RFC 9293 & https://www.iana.org/assignments/ipfix/ipfix.xhtml
#define FIN_FLAG 0x01
#define SYN_FLAG 0x02
#define RST_FLAG 0x04
#define PSH_FLAG 0x08
#define ACK_FLAG 0x10
#define URG_FLAG 0x20
#define ECE_FLAG 0x40
#define CWR_FLAG 0x80
// Custom flags exported
#define SYN_ACK_FLAG 0x100
#define FIN_ACK_FLAG 0x200
#define RST_ACK_FLAG 0x400

// In conn_initiator_key, which sorted connection inititated the connection
#define INITIATOR_LOW     1
#define INITIATOR_HIGH    2

// In flow_metrics, who initiated the connection
#define INITIATOR_SRC 1
#define INITIATOR_DST 2

#define INITIATOR_UNKNOWN 0

// Common Ringbuffer as a conduit for ingress/egress flows to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} direct_flows SEC(".maps");

// Key: the flow identifier. Value: the flow metrics for that identifier.
// The userspace will aggregate them into a single flow.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, flow_metrics);
} aggregated_flows SEC(".maps");

// Key: the flow identifier. Value: the flow direction.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, flow_id);
	__type(value, u8);
} flow_directions SEC(".maps");

// Key: the flow identifier. Value: the flow direction.
// Since the same connection can be visible from different perspectives
// (Client to Server, as seen by the)
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, conn_initiator_key);
	__type(value, u8);
} conn_initiators SEC(".maps");

const u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

// Constant definitions, to be overridden by the invoker
volatile const u32 sampling = 0;
volatile const u8 trace_messages = 0;


#endif //__FLOW_HELPERS_H__