#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/http_types.h>
#include <common/pin_internal.h>
#include <common/ringbuf.h>
#include <common/trace_common.h>

#include <generictracer/protocol_common.h>

// Keeps track of tcp buffers for unknown protocols
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t);
    __type(value, tcp_req_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} ongoing_tcp_req SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, tcp_req_t);
    __uint(max_entries, 1);
} tcp_req_mem SEC(".maps");

static __always_inline tcp_req_t *empty_tcp_req() {
    int zero = 0;
    tcp_req_t *value = bpf_map_lookup_elem(&tcp_req_mem, &zero);
    if (value) {
        __builtin_memset(value, 0, sizeof(tcp_req_t));
    }
    return value;
}

static __always_inline void init_new_trace(tp_info_t *tp) {
    new_trace_id(tp);
    urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);
    __builtin_memset(tp->parent_id, 0, sizeof(tp->span_id));
}

static __always_inline void
set_tcp_trace_info(u32 type, connection_info_t *conn, tp_info_t *tp, u32 pid, u8 ssl) {
    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        return;
    }

    tp_p->tp = *tp;
    tp_p->tp.flags = 1;
    tp_p->valid = 1;
    tp_p->pid = pid; // used for avoiding finding stale server requests with client port reuse
    tp_p->req_type = EVENT_TCP_REQUEST;

    set_trace_info_for_connection(conn, type, tp_p);
    bpf_dbg_printk("Set traceinfo for conn");
    dbg_print_http_connection_info(conn);

    server_or_client_trace(type, conn, tp_p, ssl);
}

static __always_inline void
tcp_get_or_set_trace_info(tcp_req_t *req, pid_connection_info_t *pid_conn, u8 ssl) {
    if (req->direction == TCP_SEND) { // Client
        u8 found = find_trace_for_client_request(pid_conn, &req->tp);
        bpf_dbg_printk("Looking up client trace info, found %d", found);
        if (found) {
            urand_bytes(req->tp.span_id, SPAN_ID_SIZE_BYTES);
        } else {
            init_new_trace(&req->tp);
        }

        set_tcp_trace_info(TRACE_TYPE_CLIENT, &pid_conn->conn, &req->tp, pid_conn->pid, ssl);
    } else { // Server
        u8 found = find_trace_for_server_request(&pid_conn->conn, &req->tp);
        bpf_dbg_printk("Looking up server trace info, found %d", found);
        if (found) {
            urand_bytes(req->tp.span_id, SPAN_ID_SIZE_BYTES);
        } else {
            init_new_trace(&req->tp);
        }
        set_tcp_trace_info(TRACE_TYPE_SERVER, &pid_conn->conn, &req->tp, pid_conn->pid, ssl);
    }
}

static __always_inline void cleanup_trace_info(tcp_req_t *tcp, pid_connection_info_t *pid_conn) {
    if (tcp->direction == TCP_RECV) {
        trace_key_t t_key = {0};
        task_tid(&t_key.p_key);
        t_key.extra_id = tcp->extra_id;

        delete_server_trace(&t_key);
    } else {
        delete_client_trace_info(pid_conn);
    }
}

static __always_inline void handle_unknown_tcp_connection(pid_connection_info_t *pid_conn,
                                                          void *u_buf,
                                                          int bytes_len,
                                                          u8 direction,
                                                          u8 ssl,
                                                          u16 orig_dport) {
    tcp_req_t *existing = bpf_map_lookup_elem(&ongoing_tcp_req, pid_conn);
    if (existing) {
        if (existing->direction == direction && existing->end_monotime_ns != 0) {
            bpf_map_delete_elem(&ongoing_tcp_req, pid_conn);
            existing = 0;
        }
    }
    if (!existing) {
        if (direction == TCP_RECV) {
            cp_support_data_t *tk = bpf_map_lookup_elem(&cp_support_connect_info, pid_conn);
            if (tk && tk->real_client) {
                bpf_dbg_printk("Got receive as first operation for client connection, ignoring...");
                return;
            }
        }

        tcp_req_t *req = empty_tcp_req();
        if (req) {
            req->flags = EVENT_TCP_REQUEST;
            req->conn_info = pid_conn->conn;
            fixup_connection_info(&req->conn_info, direction, orig_dport);
            req->ssl = ssl;
            req->direction = direction;
            req->start_monotime_ns = bpf_ktime_get_ns();
            req->end_monotime_ns = 0;
            req->resp_len = 0;
            req->len = bytes_len;
            req->req_len = req->len;
            req->extra_id = extra_runtime_id();
            task_pid(&req->pid);
            bpf_probe_read(req->buf, K_TCP_MAX_LEN, u_buf);

            req->tp.ts = bpf_ktime_get_ns();

            bpf_dbg_printk("TCP request start, direction = %d, ssl = %d", direction, ssl);

            tcp_get_or_set_trace_info(req, pid_conn, ssl);

            bpf_map_update_elem(&ongoing_tcp_req, pid_conn, req, BPF_ANY);
        }
    } else if (existing->direction != direction) {
        if (existing->end_monotime_ns == 0) {
            existing->end_monotime_ns = bpf_ktime_get_ns();
            existing->resp_len = bytes_len;
            tcp_req_t *trace = bpf_ringbuf_reserve(&events, sizeof(tcp_req_t), 0);
            if (trace) {
                bpf_dbg_printk(
                    "Sending TCP trace %lx, response length %d", existing, existing->resp_len);

                __builtin_memcpy(trace, existing, sizeof(tcp_req_t));
                bpf_probe_read(trace->rbuf, K_TCP_RES_LEN, u_buf);
                bpf_ringbuf_submit(trace, get_flags());
            } else {
                bpf_printk("failed to reserve space on the ringbuf");
            }
            cleanup_trace_info(existing, pid_conn);
        }
    } else if (existing->len > 0 && existing->len < (K_TCP_MAX_LEN / 2)) {
        // Attempt to append one more packet. I couldn't convince the verifier
        // to use a variable (K_TCP_MAX_LEN-existing->len). If needed we may need
        // to try harder. Mainly needed for userspace detection of missed gRPC, where
        // the protocol may sent a RST frame after we've done creating the event, so
        // the next event has an RST frame prepended.
        u32 off = existing->len;
        bpf_clamp_umax(off, (K_TCP_MAX_LEN / 2));
        bpf_probe_read(existing->buf + off, (K_TCP_MAX_LEN / 2), u_buf);
        existing->len += bytes_len;
        existing->req_len = existing->len;
    } else {
        existing->req_len += bytes_len;
    }
}

// k_tail_protocol_tcp
SEC("kprobe/tcp")
int beyla_protocol_tcp(void *ctx) {
    call_protocol_args_t *args = protocol_args();

    if (!args) {
        return 0;
    }

    handle_unknown_tcp_connection(&args->pid_conn,
                                  (void *)args->u_buf,
                                  args->bytes_len,
                                  args->direction,
                                  args->ssl,
                                  args->orig_dport);

    return 0;
}
