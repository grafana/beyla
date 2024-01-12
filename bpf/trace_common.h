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
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} trace_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // key: pid_tid
    __type(value, tp_info_t);  // value: traceparent info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} server_traces SEC(".maps");

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

struct callback_ctx {
    unsigned char *buf;
	u32 pos;
};

#ifdef BPF_TRACEPARENT
static int tp_match(u32 index, void *data)
{
    if (index >= (TRACE_BUF_SIZE-TRACE_PARENT_HEADER_LEN)) {
        return 1;
    }

    struct callback_ctx *ctx = data;    
    unsigned char *s = &(ctx->buf[index]);

    if (is_traceparent(s)) {
        ctx->pos = index;
        return 1;
    }

    return 0;
}

static __always_inline unsigned char *bpf_strstr_tp_loop(unsigned char *buf, int buf_len) {
    struct callback_ctx data = {
        .buf = buf,
        .pos = 0
    };

    u32 nr_loops = (u32)buf_len;

    bpf_loop(nr_loops, tp_match, &data, 0);

    if (data.pos) {
        u32 pos = (data.pos > (TRACE_BUF_SIZE-TRACE_PARENT_HEADER_LEN)) ? 0 : data.pos;
        return &(buf[pos]);
    }

    return 0;
}
#endif

// Traceparent format: Traceparent: ver (2 chars) - trace_id (32 chars) - span_id (16 chars) - flags (2 chars)
static __always_inline unsigned char *extract_trace_id(unsigned char *tp_start) {
    return tp_start + 13 + 2 + 1; // strlen("Traceparent: ") + strlen(ver) + strlen('-')
}

static __always_inline unsigned char *extract_span_id(unsigned char *tp_start) {
    return tp_start + 13 + 2 + 1 + 32 + 1; // strlen("Traceparent: ") + strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-")
}

static __always_inline unsigned char *extract_flags(unsigned char *tp_start) {
    return tp_start + 13 + 2 + 1 + 32 + 1 + 16 + 1; // strlen("Traceparent: ") + strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-") + strlen(span_id) + strlen("-")
}

static __always_inline u64 current_epoch(u64 ts) {
    u64 temp = ts / NANOSECONDS_PER_EPOCH;
    return temp * NANOSECONDS_PER_EPOCH;
}

static __always_inline void server_or_client_trace(http_connection_metadata_t *meta, connection_info_t *conn, tp_info_t *tp) {
    if (!meta) {
        return;
    }
    if (meta->type == EVENT_HTTP_REQUEST) {
        u64 pid_tid = bpf_get_current_pid_tgid();
        bpf_dbg_printk("Saving server span for id=%llx", pid_tid);
        bpf_map_update_elem(&server_traces, &pid_tid, tp, BPF_ANY);
    }
}

static __always_inline u8 correlated_requests(tp_info_t *tp, tp_info_t *existing_tp) {
    if (!existing_tp) {
        return 0;
    }

    if (tp->ts > existing_tp->ts) {
        return current_epoch(tp->ts) == current_epoch(existing_tp->ts);
    }

    return 0;
}

static __always_inline tp_info_t *trace_info_for_connection(connection_info_t *conn) {
    return (tp_info_t *)bpf_map_lookup_elem(&trace_map, conn);
}

static __always_inline void get_or_create_trace_info(http_connection_metadata_t *meta, connection_info_t *conn, void *u_buf, int bytes_len, s32 capture_header_buffer) {
    tp_info_t *tp = tp_buf();

    if (!tp) {
        return;
    }

    tp->ts = bpf_ktime_get_ns();
    tp->flags = 1;
    urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);

    u8 found_tp = 0;

    if (meta) {
        if (meta->type == EVENT_HTTP_CLIENT) {
            u64 pid_tid = bpf_get_current_pid_tgid();
            tp_info_t *server_tp = bpf_map_lookup_elem(&server_traces, &pid_tid);

            if (server_tp) {
                found_tp = 1;
                bpf_dbg_printk("Found existing server tp for client call");
                bpf_memcpy(tp->trace_id, server_tp->trace_id, sizeof(tp->trace_id));
                bpf_memcpy(tp->parent_id, server_tp->span_id, sizeof(tp->parent_id));
            }
        } else {
            tp_info_t *existing_tp = trace_info_for_connection(conn);

            if (correlated_requests(tp, existing_tp)) {
                found_tp = 1;
                bpf_dbg_printk("Found existing correlated tp for server request");
                bpf_memcpy(tp->trace_id, existing_tp->trace_id, sizeof(tp->trace_id));
                bpf_memcpy(tp->parent_id, existing_tp->span_id, sizeof(tp->parent_id));
            } 
        }
    }
    
    if (!found_tp) {
        urand_bytes(tp->trace_id, TRACE_ID_SIZE_BYTES);
        bpf_memset(tp->parent_id, 0, sizeof(tp->span_id));
    }

#ifdef BPF_TRACEPARENT
    // The below buffer scan can be expensive on high volume of requests. We make it optional
    // for customers to enable it. Off by default.
    if (!capture_header_buffer || !bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_loop)) {    
        bpf_map_update_elem(&trace_map, conn, tp, BPF_ANY);
        server_or_client_trace(meta, conn, tp);
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
            bpf_dbg_printk("Found traceparent %s", res);
            unsigned char *t_id = extract_trace_id(res);
            unsigned char *s_id = extract_span_id(res);
            unsigned char *f_id = extract_flags(res);

            decode_hex(tp->trace_id, t_id, TRACE_ID_CHAR_LEN);
            decode_hex((unsigned char *)&tp->flags, f_id, FLAGS_CHAR_LEN);
            if (meta && meta->type == EVENT_HTTP_CLIENT) {
                decode_hex(tp->span_id, s_id, SPAN_ID_CHAR_LEN);
            } else {
                decode_hex(tp->parent_id, s_id, SPAN_ID_CHAR_LEN);
            }
        } else {
            bpf_dbg_printk("No traceparent, making a new trace_id", res);
        }
    } else {
        return;
    }
#endif

    bpf_map_update_elem(&trace_map, conn, tp, BPF_ANY);
    server_or_client_trace(meta, conn, tp);

    return;
}

static __always_inline u8 valid_span(unsigned char *span_id) {
    return *((u64 *)span_id) != 0;
}

#endif