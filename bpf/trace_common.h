#ifndef TRACE_COMMON_H
#define TRACE_COMMON_H

#include "utils.h"
#include "http_types.h"
#include "trace_util.h"

#define NANOSECONDS_PER_EPOCH (15LL * 1000000000LL) // 15 seconds

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t); // key: the connection info
    __type(value, tp_info_t);  // value: traceparent info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} trace_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, tp_info_t);
    __uint(max_entries, 1);
} tp_info_mem SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, unsigned char[TRACE_BUF_SIZE]);
    __uint(max_entries, 1);
} tp_char_buf_mem SEC(".maps");

static __always_inline unsigned char *tp_char_buf() {
    int zero = 0;
    return bpf_map_lookup_elem(&tp_char_buf_mem, &zero);
}

static __always_inline tp_info_t *tp_buf() {
    int zero = 0;
    return bpf_map_lookup_elem(&tp_info_mem, &zero);
}

// Traceparent format: Traceparent: ver (2 chars) - trace_id (32 chars) - span_id (16 chars) - flags (2 chars)
static __always_inline unsigned char *extract_trace_id(unsigned char *tp_start) {
    return tp_start + 13 + 2 + 1; // strlen("Traceparent: ") + strlen(ver) + strlen('-')
}

static __always_inline unsigned char *extract_span_id(unsigned char *tp_start) {
    return tp_start + 13 + 2 + 1 + 32 + 1; // strlen("Traceparent: ") + strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-")
}

static __always_inline u64 current_epoch() {
    u64 ts = bpf_ktime_get_ns();
    u64 temp = ts / NANOSECONDS_PER_EPOCH;
    return temp * NANOSECONDS_PER_EPOCH;
}

static __always_inline void get_or_create_trace_info(connection_info_t *conn, void *u_buf, int bytes_len, s32 capture_header_buffer) {
    tp_info_t *tp = tp_buf();

    if (!tp) {
        return;
    }

    tp->epoch = current_epoch();

    // The below buffer scan can be expensive on high volume of requests. We make it optional
    // for customers to enable it. Off by default.
    if (!capture_header_buffer || !bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_loop)) {
        urand_bytes(tp->trace_id, TRACE_ID_SIZE_BYTES);
        bpf_memset(tp->parent_id, 0, sizeof(tp->span_id));
        urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);

        bpf_map_update_elem(&trace_map, conn, tp, BPF_ANY);
        return;
    }

    unsigned char *buf = tp_char_buf();
    if (buf) {        
        s64 buf_len = (s64)bytes_len;
        if (buf_len >= TRACE_BUF_SIZE) {
            buf_len = TRACE_BUF_SIZE - 1;
        }
        buf_len &= (TRACE_BUF_SIZE - 1);

        bpf_probe_read(buf, buf_len, u_buf);
        unsigned char *res = bpf_strstr_tp_loop(buf, buf_len);

        if (res) {
            bpf_dbg_printk("Found buf %s", res);
            unsigned char *t_id = extract_trace_id(res);
            unsigned char *s_id = extract_span_id(res);

            decode_hex(tp->trace_id, t_id, TRACE_ID_CHAR_LEN);
            decode_hex(tp->parent_id, s_id, SPAN_ID_CHAR_LEN);
        } else {
            bpf_dbg_printk("No traceparent, making a new trace_id", res);
            urand_bytes(tp->trace_id, TRACE_ID_SIZE_BYTES);
            bpf_memset(tp->parent_id, 0, sizeof(tp->span_id));
        }            
        urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);
    } else {
        return;
    }

    bpf_map_update_elem(&trace_map, conn, tp, BPF_ANY);

    return;
}

static __always_inline tp_info_t *trace_info_for_connection(connection_info_t *conn) {
    return (tp_info_t *)bpf_map_lookup_elem(&trace_map, conn);
}

#endif