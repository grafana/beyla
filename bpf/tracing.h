#ifndef TRACING_H
#define TRACING_H
#include "vmlinux.h"
#include "trace_util.h"
#include "http_types.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t); // key: the connection info
    __type(value, tp_info_pid_t);  // value: traceparent info
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} trace_map SEC(".maps");

static __always_inline void make_tp_string(unsigned char *buf, tp_info_t *tp) {
    // Version
    *buf++ = '0'; *buf++ = '0'; *buf++ = '-';

    // TraceID
    encode_hex(buf, tp->trace_id, TRACE_ID_SIZE_BYTES);
    buf += TRACE_ID_CHAR_LEN;
    *buf++ = '-';

    // SpanID
    encode_hex(buf, tp->span_id, SPAN_ID_SIZE_BYTES);
    buf += SPAN_ID_CHAR_LEN;
    *buf++ = '-';

    // Flags
    *buf++ = '0'; *buf = (tp->flags == 0) ? '0' : '1';
}

static __always_inline tp_info_pid_t *trace_info_for_connection(connection_info_t *conn) {
    return (tp_info_pid_t *)bpf_map_lookup_elem(&trace_map, conn);
}

static __always_inline void delete_trace_info_for_connection(connection_info_t *conn) {
    bpf_map_delete_elem(&trace_map, conn);
}

#endif