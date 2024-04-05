#ifndef TRACING_H
#define TRACING_H
#include "vmlinux.h"
#include "trace_util.h"
#include "http_types.h"

#define NANOSECONDS_PER_EPOCH (15LL * 1000000000LL) // 15 seconds
#define NANOSECONDS_PER_IMM_EPOCH (100000000LL) // 100 ms

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

static __always_inline u64 current_epoch(u64 ts) {
    u64 temp = ts / NANOSECONDS_PER_EPOCH;
    return temp * NANOSECONDS_PER_EPOCH;
}

static __always_inline u64 current_immediate_epoch(u64 ts) {
    u64 temp = ts / NANOSECONDS_PER_IMM_EPOCH;
    return temp * NANOSECONDS_PER_IMM_EPOCH;
}

static __always_inline u8 correlated_requests(tp_info_pid_t *tp, tp_info_pid_t *existing_tp) {
    if (!existing_tp) {
        return 0;
    }

    // We check for correlated requests which are in order, but from different PIDs
    // Same PID means that we had client port reuse, which might falsely match prior
    // transaction if it happened during the same epoch.
    if ((tp->tp.ts >= existing_tp->tp.ts) && (tp->pid != existing_tp->pid)) {
        return current_epoch(tp->tp.ts) == current_epoch(existing_tp->tp.ts);
    }

    return 0;
}

static __always_inline u8 correlated_request_with_current(tp_info_pid_t *existing_tp) {
    if (!existing_tp) {
        return 0;
    }

    u64 pid_tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    u32 pid= pid_from_pid_tgid(pid_tid);

    // We check for correlated requests which are in order, but from different PIDs
    // Same PID means that we had client port reuse, which might falsely match prior
    // transaction if it happened during the same epoch.
    if ((ts >= existing_tp->tp.ts) && (pid != existing_tp->pid)) {
        return current_epoch(ts) == current_epoch(existing_tp->tp.ts);
    }

    return 0;
}

#endif