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

#ifdef BPF_TRACEPARENT
enum { k_bpf_traceparent_enabled = 1 };
#else
enum { k_bpf_traceparent_enabled = 0 };
#endif

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

static int tp_match(u32 index, void *data) {
    if (!k_bpf_traceparent_enabled) {
        return 0;
    }

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
    if (!k_bpf_traceparent_enabled) {
        return NULL;
    }

    struct callback_ctx data = {.buf = buf, .pos = 0};

    u32 nr_loops = (u32)buf_len;

    bpf_loop(nr_loops, tp_match, &data, 0);

    if (data.pos) {
        return (data.pos > (TRACE_BUF_SIZE - TRACE_PARENT_HEADER_LEN)) ? NULL : &(buf[data.pos]);
    }

    return NULL;
}

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

    delete_trace_info_for_connection(&pid_conn->conn, TRACE_TYPE_CLIENT);

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
    return *((u64 *)trace_id) != 0 || *((u64 *)(trace_id + 8)) != 0;
}

static __always_inline void
server_or_client_trace(u8 type, connection_info_t *conn, tp_info_pid_t *tp_p, u8 ssl) {
    if (type == EVENT_HTTP_REQUEST) {
        trace_key_t t_key = {0};
        task_tid(&t_key.p_key);
        t_key.extra_id = extra_runtime_id();

        tp_info_pid_t *existing = bpf_map_lookup_elem(&server_traces, &t_key);
        // We have a conflict, mark this invalid and do nothing
        // We look for conflicts on HTTP requests only and only with other HTTP requests,
        // since TCP requests can come one after another and with SSL we can have a mix
        // of TCP and HTTP requests.
        if (existing && (existing->req_type == tp_p->req_type) &&
            (tp_p->req_type == EVENT_HTTP_REQUEST)) {
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

        if (ssl) {
            // Clone and mark it invalid for the purpose of storing it in the
            // outgoing trace map, if it's an SSL connection
            tp_info_pid_t tp_p_invalid = {0};
            __builtin_memcpy(&tp_p_invalid, tp_p, sizeof(tp_p_invalid));
            tp_p_invalid.valid = 0;
            bpf_map_update_elem(&outgoing_trace_map, &e_key, &tp_p_invalid, BPF_ANY);
        } else {
            bpf_map_update_elem(&outgoing_trace_map, &e_key, tp_p, BPF_ANY);
        }
    }
}

static __always_inline u8 find_trace_for_server_request(connection_info_t *conn, tp_info_t *tp) {
    u8 found_tp = 0;
    tp_info_pid_t *existing_tp = bpf_map_lookup_elem(&incoming_trace_map, conn);
    if (existing_tp) {
        found_tp = 1;
        bpf_dbg_printk("Found incoming (TCP) tp for server request");
        __builtin_memcpy(tp->trace_id, existing_tp->tp.trace_id, sizeof(tp->trace_id));
        __builtin_memcpy(tp->parent_id, existing_tp->tp.span_id, sizeof(tp->parent_id));
        bpf_map_delete_elem(&incoming_trace_map, conn);
    } else {
        bpf_dbg_printk("Looking up tracemap for");
        dbg_print_http_connection_info(conn);

        existing_tp = trace_info_for_connection(conn, TRACE_TYPE_CLIENT);

        bpf_dbg_printk("existing_tp %llx", existing_tp);

        if (!disable_black_box_cp && correlated_requests(tp, existing_tp)) {
            found_tp = 1;
            bpf_dbg_printk("Found existing correlated tp for server request");
            __builtin_memcpy(tp->trace_id, existing_tp->tp.trace_id, sizeof(tp->trace_id));
            __builtin_memcpy(tp->parent_id, existing_tp->tp.span_id, sizeof(tp->parent_id));
        }
    }

    return found_tp;
}

static __always_inline u8 find_trace_for_client_request(pid_connection_info_t *p_conn,
                                                        tp_info_t *tp) {
    u8 found_tp = 0;
    tp_info_pid_t *server_tp = find_parent_trace(p_conn);
    if (server_tp && server_tp->valid && valid_trace(server_tp->tp.trace_id)) {
        found_tp = 1;
        bpf_dbg_printk("Found existing server tp for client call");
        __builtin_memcpy(tp->trace_id, server_tp->tp.trace_id, sizeof(tp->trace_id));
        __builtin_memcpy(tp->parent_id, server_tp->tp.span_id, sizeof(tp->parent_id));
    }

    return found_tp;
}

#endif
