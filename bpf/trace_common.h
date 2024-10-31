#ifndef TRACE_COMMON_H
#define TRACE_COMMON_H

#include "utils.h"
#include "http_types.h"
#include "trace_util.h"
#include "tracing.h"
#include "pid_types.h"
#include "runtime.h"
#include "ringbuf.h"
#include "pin_internal.h"

typedef struct trace_key {
    pid_key_t p_key; // pid key as seen by the userspace (for example, inside its container)
    u64 extra_id;    // pids namespace for the process
} __attribute__((packed)) trace_key_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, trace_key_t);     // key: pid_tid
    __type(value, tp_info_pid_t); // value: traceparent info
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} server_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, tp_info_pid_t);
    __uint(max_entries, 1);
} tp_info_mem SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, unsigned char[TRACE_BUF_SIZE]);
    __uint(max_entries, 1);
} tp_char_buf_mem SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_key_t);   // key: the child pid
    __type(value, pid_key_t); // value: the parent pid
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} clone_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t); // key: conn_info
    __type(value, trace_key_t);         // value: tracekey to lookup in server_traces
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} client_connect_info SEC(".maps");

static __always_inline unsigned char *tp_char_buf() {
    int zero = 0;
    return bpf_map_lookup_elem(&tp_char_buf_mem, &zero);
}

static __always_inline tp_info_pid_t *tp_buf() {
    int zero = 0;
    return bpf_map_lookup_elem(&tp_info_mem, &zero);
}

struct callback_ctx {
    unsigned char *buf;
    u32 pos;
};

#ifdef BPF_TRACEPARENT
static int tp_match(u32 index, void *data) {
    if (index >= (TRACE_BUF_SIZE - TRACE_PARENT_HEADER_LEN)) {
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
    struct callback_ctx data = {.buf = buf, .pos = 0};

    u32 nr_loops = (u32)buf_len;

    bpf_loop(nr_loops, tp_match, &data, 0);

    if (data.pos) {
        return (data.pos > (TRACE_BUF_SIZE - TRACE_PARENT_HEADER_LEN)) ? NULL : &(buf[data.pos]);
    }

    return NULL;
}
#endif

static __always_inline tp_info_pid_t *find_parent_trace(pid_connection_info_t *p_conn) {
    trace_key_t t_key = {0};

    task_tid(&t_key.p_key);
    u64 extra_id = extra_runtime_id();
    t_key.extra_id = extra_id;

    int attempts = 0;

    do {
        tp_info_pid_t *server_tp = bpf_map_lookup_elem(&server_traces, &t_key);

        if (!server_tp) { // not this goroutine running the server request processing
            // Let's find the parent scope
            if (t_key.extra_id) {
                u64 parent_id = parent_runtime_id(&t_key.p_key, t_key.extra_id);
                if (parent_id) {
                    t_key.extra_id = parent_id;
                } else {
                    break;
                }
            } else {
                pid_key_t *p_tid = (pid_key_t *)bpf_map_lookup_elem(&clone_map, &t_key.p_key);
                if (p_tid) {
                    // Lookup now to see if the parent was a request
                    t_key.p_key = *p_tid;
                } else {
                    break;
                }
            }
        } else {
            //bpf_dbg_printk("Found parent trace for pid=%d, ns=%lx, orig_extra_id=%llx, extra_id=%llx", t_key.p_key.pid, t_key.p_key.ns, extra_id, t_key.extra_id);
            return server_tp;
        }

        attempts++;
    } while (attempts < 3); // Up to 3 levels of thread nesting allowed

    trace_key_t *conn_t_key = bpf_map_lookup_elem(&client_connect_info, p_conn);

    if (conn_t_key) {
        return bpf_map_lookup_elem(&server_traces, conn_t_key);
    }

    return 0;
}

// Traceparent format: Traceparent: ver (2 chars) - trace_id (32 chars) - span_id (16 chars) - flags (2 chars)
static __always_inline unsigned char *extract_trace_id(unsigned char *tp_start) {
    return tp_start + 13 + 2 + 1; // strlen("Traceparent: ") + strlen(ver) + strlen('-')
}

static __always_inline unsigned char *extract_span_id(unsigned char *tp_start) {
    return tp_start + 13 + 2 + 1 + 32 +
           1; // strlen("Traceparent: ") + strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-")
}

static __always_inline unsigned char *extract_flags(unsigned char *tp_start) {
    return tp_start + 13 + 2 + 1 + 32 + 1 + 16 +
           1; // strlen("Traceparent: ") + strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-") + strlen(span_id) + strlen("-")
}

static __always_inline void delete_server_trace(trace_key_t *t_key) {
    int __attribute__((unused)) res = bpf_map_delete_elem(&server_traces, t_key);
    // Fails on 5.10 with unknown function
    // bpf_dbg_printk("Deleting server span for id=%llx, pid=%d, ns=%d, res = %d", bpf_get_current_pid_tgid(), t_key->p_key.pid, t_key->p_key.ns, res);
}

static __always_inline void delete_client_trace_info(pid_connection_info_t *pid_conn) {
    bpf_dbg_printk("Deleting client trace map for connection");
    dbg_print_http_connection_info(&pid_conn->conn);

    bpf_map_delete_elem(&trace_map, &pid_conn->conn);
    egress_key_t e_key = {
        .d_port = pid_conn->conn.d_port,
        .s_port = pid_conn->conn.s_port,
    };
    bpf_map_delete_elem(&outgoing_trace_map, &e_key);
    bpf_map_delete_elem(&client_connect_info, pid_conn);
}

static __always_inline u8 valid_span(const unsigned char *span_id) {
    return *((u64 *)span_id) != 0;
}

static __always_inline u8 valid_trace(const unsigned char *trace_id) {
    return *((u64 *)trace_id) != 0 && *((u64 *)(trace_id + 8)) != 0;
}

static __always_inline void server_or_client_trace(http_connection_metadata_t *meta,
                                                   connection_info_t *conn,
                                                   tp_info_pid_t *tp_p) {
    if (!meta) {
        return;
    }
    if (meta->type == EVENT_HTTP_REQUEST) {
        trace_key_t t_key = {0};
        task_tid(&t_key.p_key);
        t_key.extra_id = extra_runtime_id();

        tp_info_pid_t *existing = bpf_map_lookup_elem(&server_traces, &t_key);
        // we have a conflict, mark this invalid and do nothing
        if (existing) {
            bpf_dbg_printk("Found conflicting server span, marking as invalid, id=%llx",
                           bpf_get_current_pid_tgid());
            existing->valid = 0;
            return;
        }

        // bpf_dbg_printk("Saving server span for id=%llx, pid=%d, ns=%d, extra_id=%llx", bpf_get_current_pid_tgid(), t_key.p_key.pid, t_key.p_key.ns, t_key.extra_id);
        bpf_map_update_elem(&server_traces, &t_key, tp_p, BPF_ANY);
    } else {
        // Setup a pid, so that we can find it in TC.
        // We need the PID id to be able to query ongoing_http and update
        // the span id with the SEQ/ACK pair.
        u64 id = bpf_get_current_pid_tgid();
        tp_p->pid = pid_from_pid_tgid(id);
        egress_key_t e_key = {
            .d_port = conn->d_port,
            .s_port = conn->s_port,
        };

        bpf_map_update_elem(&outgoing_trace_map, &e_key, tp_p, BPF_ANY);
    }
}

static __always_inline void get_or_create_trace_info(http_connection_metadata_t *meta,
                                                     u32 pid,
                                                     connection_info_t *conn,
                                                     void *u_buf,
                                                     int bytes_len,
                                                     s32 capture_header_buffer) {
    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        return;
    }

    tp_p->tp.ts = bpf_ktime_get_ns();
    tp_p->tp.flags = 1;
    tp_p->valid = 1;
    tp_p->pid = pid; // used for avoiding finding stale server requests with client port reuse

    urand_bytes(tp_p->tp.span_id, SPAN_ID_SIZE_BYTES);

    u8 found_tp = 0;

    if (meta) {
        if (meta->type == EVENT_HTTP_CLIENT) {
            pid_connection_info_t p_conn = {.pid = pid};
            __builtin_memcpy(&p_conn.conn, conn, sizeof(connection_info_t));
            tp_info_pid_t *server_tp = find_parent_trace(&p_conn);

            if (server_tp && server_tp->valid && valid_trace(server_tp->tp.trace_id)) {
                found_tp = 1;
                bpf_dbg_printk("Found existing server tp for client call");
                __builtin_memcpy(
                    tp_p->tp.trace_id, server_tp->tp.trace_id, sizeof(tp_p->tp.trace_id));
                __builtin_memcpy(
                    tp_p->tp.parent_id, server_tp->tp.span_id, sizeof(tp_p->tp.parent_id));
            }
        } else {
            //bpf_dbg_printk("Looking up existing trace for connection");
            //dbg_print_http_connection_info(conn);

            // For server requests, we first look for TCP info (setup by TC ingress) and then we fall back to black-box info.
            tp_info_pid_t *existing_tp = bpf_map_lookup_elem(&incoming_trace_map, conn);
            if (existing_tp) {
                found_tp = 1;
                bpf_dbg_printk("Found incoming (TCP) tp for server request");
                __builtin_memcpy(
                    tp_p->tp.trace_id, existing_tp->tp.trace_id, sizeof(tp_p->tp.trace_id));
                __builtin_memcpy(
                    tp_p->tp.parent_id, existing_tp->tp.span_id, sizeof(tp_p->tp.parent_id));
                bpf_map_delete_elem(&incoming_trace_map, conn);
            } else {
                existing_tp = trace_info_for_connection(conn);

                if (!disable_black_box_cp && correlated_requests(tp_p, existing_tp)) {
                    found_tp = 1;
                    bpf_dbg_printk("Found existing correlated tp for server request");
                    __builtin_memcpy(
                        tp_p->tp.trace_id, existing_tp->tp.trace_id, sizeof(tp_p->tp.trace_id));
                    __builtin_memcpy(
                        tp_p->tp.parent_id, existing_tp->tp.span_id, sizeof(tp_p->tp.parent_id));
                }
            }
        }
    }

    if (!found_tp) {
        bpf_dbg_printk("Generating new traceparent id");
        new_trace_id(&tp_p->tp);
        __builtin_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.span_id));
    } else {
        bpf_dbg_printk("Using old traceparent id");
    }

    //unsigned char tp_buf[TP_MAX_VAL_LENGTH];
    //make_tp_string(tp_buf, &tp_p->tp);
    //bpf_dbg_printk("tp: %s", tp_buf);

#ifdef BPF_TRACEPARENT
    // The below buffer scan can be expensive on high volume of requests. We make it optional
    // for customers to enable it. Off by default.
    if (!capture_header_buffer) {
        set_trace_info_for_connection(conn, tp_p);
        server_or_client_trace(meta, conn, tp_p);
        return;
    }

    unsigned char *buf = tp_char_buf();
    if (buf) {
        int buf_len = bytes_len;
        bpf_clamp_umax(buf_len, TRACE_BUF_SIZE - 1);

        bpf_probe_read(buf, buf_len, u_buf);
        unsigned char *res = bpf_strstr_tp_loop(buf, buf_len);

        if (res) {
            bpf_dbg_printk("Found traceparent %s", res);
            unsigned char *t_id = extract_trace_id(res);
            unsigned char *s_id = extract_span_id(res);
            unsigned char *f_id = extract_flags(res);

            decode_hex(tp_p->tp.trace_id, t_id, TRACE_ID_CHAR_LEN);
            decode_hex((unsigned char *)&tp_p->tp.flags, f_id, FLAGS_CHAR_LEN);
            if (meta && meta->type == EVENT_HTTP_CLIENT) {
                decode_hex(tp_p->tp.span_id, s_id, SPAN_ID_CHAR_LEN);
            } else {
                decode_hex(tp_p->tp.parent_id, s_id, SPAN_ID_CHAR_LEN);
            }
        } else {
            bpf_dbg_printk("No traceparent, making a new trace_id", res);
        }
    } else {
        return;
    }
#endif

    set_trace_info_for_connection(conn, tp_p);
    server_or_client_trace(meta, conn, tp_p);
}

#endif
