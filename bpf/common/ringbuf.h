#pragma once

#include <bpfcore/utils.h>

#include <common/pin_internal.h>

// These need to line up with some Go identifiers:
// EventTypeHTTP, EventTypeGRPC, EventTypeHTTPClient, EventTypeGRPCClient, EventTypeSQLClient, EventTypeKHTTPRequest
#define EVENT_HTTP_REQUEST 1
#define EVENT_GRPC_REQUEST 2
#define EVENT_HTTP_CLIENT 3
#define EVENT_GRPC_CLIENT 4
#define EVENT_SQL_CLIENT 5
#define EVENT_K_HTTP_REQUEST 6
#define EVENT_K_HTTP2_REQUEST 7
#define EVENT_TCP_REQUEST 8
#define EVENT_GO_KAFKA 9
#define EVENT_GO_REDIS 10
#define EVENT_GO_KAFKA_SEG 11 // the segment-io version (kafka-go) has different format

// setting here the following map definitions without pinning them to a global namespace
// would lead that services running both HTTP and GRPC server would duplicate
// the events ringbuffer and goroutines map.
// This is an edge inefficiency that allows us avoiding the gotchas of
// pinning maps to the global namespace (e.g. like not cleaning them up when
// the autoinstrumenter ends abruptly)
// https://ants-gitlab.inf.um.es/jorgegm/xdp-tutorial/-/blob/master/basic04-pinning-maps/README.org
// we can share them later if we find is worth not including code per duplicate
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} events SEC(".maps");

// To be Injected from the user space during the eBPF program load & initialization
volatile const u32 wakeup_data_bytes;

// get_flags prevents waking the userspace process up on each ringbuf message.
// If wakeup_data_bytes > 0, it will wait until wakeup_data_bytes are accumulated
// into the buffer before waking the userspace.
static __always_inline long get_flags() {
    long sz;

    if (!wakeup_data_bytes) {
        return 0;
    }

    sz = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA);
    return sz >= wakeup_data_bytes ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}
