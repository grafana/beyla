#pragma once

#include <bpfcore/utils.h>

#include <common/cp_support_data.h>
#include <common/http_types.h>
#include <common/pin_internal.h>
#include <common/ringbuf.h>
#include <common/runtime.h>
#include <common/trace_key.h>
#include <common/trace_util.h>
#include <common/tracing.h>

#include <maps/clone_map.h>
#include <maps/cp_support_connect_info.h>
#include <maps/fd_map.h>
#include <maps/fd_to_connection.h>
#include <maps/nginx_upstream.h>
#include <maps/nodejs_fd_map.h>
#include <maps/server_traces.h>
#include <maps/tp_info_mem.h>
#include <maps/tp_char_buf_mem.h>

#include <pid/pid_helpers.h>

#ifdef BPF_TRACEPARENT
enum { k_bpf_traceparent_enabled = 1 };
#else
enum { k_bpf_traceparent_enabled = 0 };
#endif

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
    u8 _pad[4];
};

static __always_inline void trace_key_from_pid_tid(trace_key_t *t_key) {
    task_tid(&t_key->p_key);

    u64 extra_id = extra_runtime_id();
    t_key->extra_id = extra_id;
}

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

static __always_inline const tp_info_pid_t *
find_nginx_parent_trace(const pid_connection_info_t *p_conn, u16 orig_dport) {
    connection_info_part_t client_part = {};
    populate_ephemeral_info(&client_part, &p_conn->conn, orig_dport, p_conn->pid, FD_CLIENT);
    fd_info_t *fd_info = fd_info_for_conn(&client_part);

    bpf_dbg_printk("fd_info lookup %llx, type=%d", fd_info, client_part.type);
    if (fd_info) {
        connection_info_part_t *parent = bpf_map_lookup_elem(&nginx_upstream, fd_info);
        bpf_dbg_printk("parent %llx, fd=%d, type=%d", parent, fd_info->fd, fd_info->type);
        if (parent) {
            return bpf_map_lookup_elem(&server_traces_aux, parent);
        }
    }

    return NULL;
}

static __always_inline const tp_info_pid_t *
find_nodejs_parent_trace(const pid_connection_info_t *p_conn, u16 orig_dport) {
    connection_info_part_t client_part = {};
    populate_ephemeral_info(&client_part, &p_conn->conn, orig_dport, p_conn->pid, FD_CLIENT);
    fd_info_t *fd_info = fd_info_for_conn(&client_part);

    if (!fd_info) {
        return NULL;
    }

    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const u64 client_key = (pid_tgid << 32) | fd_info->fd;

    const s32 *node_parent_request_fd = bpf_map_lookup_elem(&nodejs_fd_map, &client_key);

    if (!node_parent_request_fd) {
        return NULL;
    }

    bpf_dbg_printk("find_nodejs_parent_trace client_fd = %d, server_fd = %d",
                   fd_info->fd,
                   *node_parent_request_fd);

    const fd_key key = {.pid_tgid = pid_tgid, .fd = *node_parent_request_fd};

    const connection_info_t *conn = bpf_map_lookup_elem(&fd_to_connection, &key);

    if (!conn) {
        return NULL;
    }

    return trace_info_for_connection(conn, TRACE_TYPE_SERVER);
}

static __always_inline const tp_info_pid_t *find_parent_process_trace(trace_key_t *t_key) {
    // Up to 5 levels of thread nesting allowed
    enum { k_max_depth = 5 };

    for (u8 i = 0; i < k_max_depth; ++i) {
        const tp_info_pid_t *server_tp = bpf_map_lookup_elem(&server_traces, t_key);

        if (server_tp) {
            bpf_dbg_printk("Found parent trace for pid=%d, ns=%lx, extra_id=%llx",
                           t_key->p_key.pid,
                           t_key->p_key.ns,
                           t_key->extra_id);
            return server_tp;
        }

        // not this goroutine running the server request processing
        // Let's find the parent scope
        const pid_key_t *p_tid = (const pid_key_t *)bpf_map_lookup_elem(&clone_map, &t_key->p_key);

        if (!p_tid) {
            break;
        }

        // Lookup now to see if the parent was a request
        t_key->p_key = *p_tid;
    }

    return NULL;
}

static __always_inline const tp_info_pid_t *find_parent_trace(const pid_connection_info_t *p_conn,
                                                              u16 orig_dport) {
    const tp_info_pid_t *node_tp = find_nodejs_parent_trace(p_conn, orig_dport);

    if (node_tp) {
        return node_tp;
    }

    trace_key_t t_key = {0};

    trace_key_from_pid_tid(&t_key);

    bpf_dbg_printk("Looking up parent trace for pid=%d, ns=%lx, extra_id=%llx",
                   t_key.p_key.pid,
                   t_key.p_key.ns,
                   t_key.extra_id);

    const tp_info_pid_t *nginx_parent = find_nginx_parent_trace(p_conn, orig_dport);

    if (nginx_parent) {
        return nginx_parent;
    }

    const tp_info_pid_t *proc_parent = find_parent_process_trace(&t_key);

    if (proc_parent) {
        return proc_parent;
    }

    const cp_support_data_t *conn_t_key = bpf_map_lookup_elem(&cp_support_connect_info, p_conn);

    if (conn_t_key) {
        bpf_dbg_printk("Found parent trace for connection through connection lookup");
        return bpf_map_lookup_elem(&server_traces, &conn_t_key->t_key);
    }

    return 0;
}

// Traceparent format: Traceparent: ver (2 chars) - trace_id (32 chars) - span_id (16 chars) - flags (2 chars)
static __always_inline unsigned char *extract_trace_id(unsigned char *tp_start) {
    return tp_start + 13 + 2 + 1; // strlen("Traceparent: ") + strlen(ver) + strlen('-')
}

static __always_inline unsigned char *extract_span_id(unsigned char *tp_start) {
    // strlen("Traceparent: ") + strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-")
    return tp_start + 13 + 2 + 1 + 32 + 1;
}

static __always_inline unsigned char *extract_flags(unsigned char *tp_start) {
    // strlen("Traceparent: ") + strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-") + strlen(span_id) + strlen("-")
    return tp_start + 13 + 2 + 1 + 32 + 1 + 16 + 1;
}

static __always_inline void delete_server_trace(pid_connection_info_t *pid_conn,
                                                trace_key_t *t_key) {
    delete_trace_info_for_connection(&pid_conn->conn, TRACE_TYPE_SERVER);
    int __attribute__((unused)) res = bpf_map_delete_elem(&server_traces, t_key);
    bpf_dbg_printk("Deleting server span for id=%llx, pid=%d, ns=%d",
                   bpf_get_current_pid_tgid(),
                   t_key->p_key.pid,
                   t_key->p_key.ns);
    bpf_dbg_printk("Deleting server span for res = %d", res);
}

static __always_inline void delete_client_trace_info(pid_connection_info_t *pid_conn) {
    bpf_dbg_printk("Deleting client trace map for connection, pid = %d", pid_conn->pid);
    dbg_print_http_connection_info(&pid_conn->conn);

    delete_trace_info_for_connection(&pid_conn->conn, TRACE_TYPE_CLIENT);

    egress_key_t e_key = {
        .d_port = pid_conn->conn.d_port,
        .s_port = pid_conn->conn.s_port,
    };
    bpf_map_delete_elem(&outgoing_trace_map, &e_key);
    bpf_map_delete_elem(&cp_support_connect_info, pid_conn);
}

static __always_inline u8 valid_span(const unsigned char *span_id) {
    return *((u64 *)span_id) != 0;
}

static __always_inline u8 valid_trace(const unsigned char *trace_id) {
    return *((u64 *)trace_id) != 0 || *((u64 *)(trace_id + 8)) != 0;
}

static __always_inline void server_or_client_trace(
    u8 type, connection_info_t *conn, tp_info_pid_t *tp_p, u8 ssl, u16 orig_dport) {

    u64 id = bpf_get_current_pid_tgid();
    u32 host_pid = pid_from_pid_tgid(id);

    if (type == EVENT_HTTP_REQUEST) {
        trace_key_t t_key = {0};
        task_tid(&t_key.p_key);
        t_key.extra_id = extra_runtime_id();

        connection_info_part_t conn_part = {};
        populate_ephemeral_info(&conn_part, conn, orig_dport, host_pid, FD_SERVER);

        bpf_dbg_printk("Saving connection server span for pid=%d, tid=%d, ephemeral_port %d",
                       t_key.p_key.pid,
                       t_key.p_key.tid,
                       conn_part.port);

        bpf_map_update_elem(&server_traces_aux, &conn_part, tp_p, BPF_ANY);

        tp_info_pid_t *existing = bpf_map_lookup_elem(&server_traces, &t_key);
        if (existing && (existing->req_type == tp_p->req_type) &&
            (tp_p->req_type == EVENT_HTTP_REQUEST)) {
            existing->valid = 0;
            bpf_dbg_printk("Found conflicting thread server span, marking it invalid.");
            return;
        }

        bpf_dbg_printk(
            "Saving thread server span for ns=%x, extra_id=%llx", t_key.p_key.ns, t_key.extra_id);
        bpf_map_update_elem(&server_traces, &t_key, tp_p, BPF_ANY);
    } else {
        // Setup a pid, so that we can find it in TC.
        // We need the PID id to be able to query ongoing_http and update
        // the span id with the SEQ/ACK pair.
        tp_p->pid = host_pid;
        const egress_key_t e_key = {
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

static __always_inline u8 find_trace_for_server_request(connection_info_t *conn,
                                                        tp_info_t *tp,
                                                        u8 type) {
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
            if (existing_tp->valid) {
                bpf_dbg_printk("Found existing correlated tp for server request");
                // Mark the client info as invalid (used), in case the client
                // request information is not cleaned up.
                if ((type == EVENT_HTTP_REQUEST && existing_tp->req_type == EVENT_HTTP_CLIENT) ||
                    (type == EVENT_TCP_REQUEST && existing_tp->req_type == EVENT_TCP_REQUEST)) {
                    found_tp = 1;
                    __builtin_memcpy(tp->trace_id, existing_tp->tp.trace_id, sizeof(tp->trace_id));
                    __builtin_memcpy(tp->parent_id, existing_tp->tp.span_id, sizeof(tp->parent_id));
                    // We ensure that server requests match the client type, otherwise SSL
                    // can often be confused with TCP.
                    existing_tp->valid = 0;
                    set_trace_info_for_connection(conn, TRACE_TYPE_CLIENT, existing_tp);
                    bpf_dbg_printk("setting the client info as used");
                } else {
                    bpf_dbg_printk("incompatible trace info, not using the correlated tp, type %d, "
                                   "other type %d",
                                   type,
                                   existing_tp->req_type);
                }
            } else {
                bpf_dbg_printk("the existing client tp was already used, ignoring");
            }
        }
    }

    return found_tp;
}

static __always_inline u8 find_trace_for_client_request(const pid_connection_info_t *p_conn,
                                                        u16 orig_dport,
                                                        tp_info_t *tp) {
    const tp_info_pid_t *server_tp = find_parent_trace(p_conn, orig_dport);

    if (server_tp && server_tp->valid && valid_trace(server_tp->tp.trace_id)) {
        bpf_dbg_printk("Found existing server tp for client call");
        __builtin_memcpy(tp->trace_id, server_tp->tp.trace_id, sizeof(tp->trace_id));
        __builtin_memcpy(tp->parent_id, server_tp->tp.span_id, sizeof(tp->parent_id));
        return 1;
    }

    return 0;
}
