#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>

#include <netolly/flow.h>

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

// In conn_initiator_key, which sorted ip:port initiated the connection
#define INITIATOR_LOW 1
#define INITIATOR_HIGH 2

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

// To know who initiated each connection, we store the src/dst ip:ports but ordered
// by numeric value of the IP (and port as secondary criteria), so the key is consistent
// for either client and server flows.
typedef struct conn_initiator_key_t {
    struct in6_addr low_ip;
    struct in6_addr high_ip;
    u16 low_ip_port;
    u16 high_ip_port;
} __attribute__((packed)) conn_initiator_key;

// Key: the flow identifier.
// Value: the connection initiator index (INITIATOR_LOW, INITIATOR_HIGH).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, conn_initiator_key);
    __type(value, u8);
} conn_initiators SEC(".maps");

const u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

// Constant definitions, to be overridden by the invoker
volatile const u32 sampling = 0;
volatile const u8 trace_messages = 0;

// we can safely assume that the passed address is IPv6 as long as we encode IPv4
// as IPv6 during the creation of the flow_id.
static inline s32 compare_ipv6(flow_id *fid) {
    for (int i = 0; i < 4; i++) {
        s32 diff = fid->src_ip.in6_u.u6_addr32[i] - fid->dst_ip.in6_u.u6_addr32[i];
        if (diff != 0) {
            return diff;
        }
    }
    return 0;
}

// creates a key that is consistent for both requests and responses, by
// ordering endpoints (ip:port) numerically into a lower and a higher endpoint.
// returns true if the lower address corresponds to the source address
// (false if the lower address corresponds to the destination address)
static inline u8 fill_conn_initiator_key(flow_id *id, conn_initiator_key *key) {
    s32 cmp = compare_ipv6(id);
    if (cmp < 0) {
        __builtin_memcpy(&key->low_ip, &id->src_ip, sizeof(struct in6_addr));
        key->low_ip_port = id->src_port;
        __builtin_memcpy(&key->high_ip, &id->dst_ip, sizeof(struct in6_addr));
        key->high_ip_port = id->dst_port;
        return 1;
    }
    // if the IPs are equal (cmp == 0) we will use the ports as secondary order criteria
    __builtin_memcpy(&key->high_ip, &id->src_ip, sizeof(struct in6_addr));
    __builtin_memcpy(&key->low_ip, &id->dst_ip, sizeof(struct in6_addr));
    if (cmp > 0 || id->src_port > id->dst_port) {
        key->high_ip_port = id->src_port;
        key->low_ip_port = id->dst_port;
        return 0;
    }
    key->low_ip_port = id->src_port;
    key->high_ip_port = id->dst_port;
    return 1;
}

// returns INITIATOR_SRC or INITIATOR_DST, but might return INITIATOR_UNKNOWN
// if the connection initiator couldn't be found. The user-space Beyla pipeline
// will handle this last case heuristically
static inline u8 get_connection_initiator(flow_id *id, u16 flags) {
    conn_initiator_key initiator_key;
    // from the initiator_key with sorted ip/ports, know the index of the
    // endpoint that that initiated the connection, which might be the low or the high address
    u8 low_is_src = fill_conn_initiator_key(id, &initiator_key);
    u8 *initiator = (u8 *)bpf_map_lookup_elem(&conn_initiators, &initiator_key);
    u8 initiator_index = INITIATOR_UNKNOWN;
    if (initiator == NULL) {
        // SYN and ACK is sent from the server to the client
        // The initiator is the destination address
        if ((flags & (SYN_FLAG | ACK_FLAG)) == (SYN_FLAG | ACK_FLAG)) {
            if (low_is_src) {
                initiator_index = INITIATOR_HIGH;
            } else {
                initiator_index = INITIATOR_LOW;
            }
        }
        // SYN is sent from the client to the server.
        // The initiator is the source address
        else if (flags & SYN_FLAG) {
            if (low_is_src) {
                initiator_index = INITIATOR_LOW;
            } else {
                initiator_index = INITIATOR_HIGH;
            }
        }

        if (initiator_index != INITIATOR_UNKNOWN) {
            bpf_map_update_elem(&conn_initiators, &initiator_key, &initiator_index, BPF_NOEXIST);
        }
    } else {
        initiator_index = *initiator;
    }

    // when flow receives FIN or RST, clean flow_directions
    if (flags & FIN_FLAG || flags & RST_FLAG || flags & FIN_ACK_FLAG || flags & RST_ACK_FLAG) {
        bpf_map_delete_elem(&conn_initiators, &initiator_key);
    }

    u8 flow_initiator = INITIATOR_UNKNOWN;
    // at this point, we should know the index of the endpoint that initiated the connection.
    // Then we accordingly set whether the initiator is the source or the destination address.
    // If not, we forward the unknown status and the userspace will take
    // heuristic actions to guess who is
    switch (initiator_index) {
    case INITIATOR_LOW:
        if (low_is_src) {
            flow_initiator = INITIATOR_SRC;
        } else {
            flow_initiator = INITIATOR_DST;
        }
        break;
    case INITIATOR_HIGH:
        if (low_is_src) {
            flow_initiator = INITIATOR_DST;
        } else {
            flow_initiator = INITIATOR_SRC;
        }
        break;
    default:
        break;
    }

    return flow_initiator;
}
