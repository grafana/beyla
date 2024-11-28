#ifndef PROTOCOL_TCP
#define PROTOCOL_TCP

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "http_types.h"
#include "ringbuf.h"
#include "protocol_common.h"
#include "trace_common.h"
#include "pin_internal.h"

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
    __builtin_memset(tp->parent_id, 0, sizeof(tp->span_id));
}

static __always_inline void
set_tcp_trace_info(u8 type, connection_info_t *conn, tp_info_t *tp, u32 pid) {
    tp_info_pid_t *tp_p = tp_buf();

    if (!tp_p) {
        return;
    }

    tp_p->tp = *tp;
    tp_p->tp.flags = 1;
    tp_p->valid = 1;
    tp_p->pid = pid; // used for avoiding finding stale server requests with client port reuse
    tp_p->type = type;

    set_trace_info_for_connection(conn, tp_p);
    bpf_dbg_printk("Set traceinfo for conn");
    dbg_print_http_connection_info(conn);

    server_or_client_trace(type, conn, tp_p);
}

static __always_inline void handle_unknown_tcp_connection(pid_connection_info_t *pid_conn,
                                                          void *u_buf,
                                                          int bytes_len,
                                                          u8 direction,
                                                          u8 ssl,
                                                          u16 orig_dport) {
    tcp_req_t *existing = bpf_map_lookup_elem(&ongoing_tcp_req, pid_conn);
    if (!existing) {
        tcp_req_t *req = empty_tcp_req();
        if (req) {
            req->flags = EVENT_TCP_REQUEST;
            req->conn_info = pid_conn->conn;
            fixup_connection_info(&req->conn_info, direction, orig_dport);
            req->ssl = ssl;
            req->direction = direction;
            req->start_monotime_ns = bpf_ktime_get_ns();
            req->len = bytes_len;
            task_pid(&req->pid);
            bpf_probe_read(req->buf, K_TCP_MAX_LEN, u_buf);

            req->tp.ts = bpf_ktime_get_ns();

            bpf_dbg_printk("TCP request start, direction = %d, ssl = %d", direction, ssl);

            if (direction == TCP_SEND) { // Client
                u8 found = find_trace_for_client_request(pid_conn, &req->tp);
                bpf_dbg_printk("Looking up client trace info, found %d", found);
                if (found) {
                    urand_bytes(req->tp.span_id, SPAN_ID_SIZE_BYTES);
                } else {
                    init_new_trace(&req->tp);
                }

                set_tcp_trace_info(EVENT_HTTP_CLIENT, &pid_conn->conn, &req->tp, pid_conn->pid);
            } else { // Server
                u8 found = find_trace_for_server_request(
                    &pid_conn->conn, &req->tp, pid_conn->pid, EVENT_HTTP_REQUEST);
                bpf_dbg_printk("Looking up server trace info, found %d", found);
                if (found) {
                    urand_bytes(req->tp.span_id, SPAN_ID_SIZE_BYTES);
                } else {
                    init_new_trace(&req->tp);
                }
                set_tcp_trace_info(EVENT_HTTP_REQUEST, &pid_conn->conn, &req->tp, pid_conn->pid);
            }

            bpf_map_update_elem(&ongoing_tcp_req, pid_conn, req, BPF_ANY);
        }
    } else if (existing->direction != direction) {
        existing->end_monotime_ns = bpf_ktime_get_ns();
        existing->resp_len = bytes_len;
        tcp_req_t *trace = bpf_ringbuf_reserve(&events, sizeof(tcp_req_t), 0);
        if (trace) {
            bpf_dbg_printk(
                "Sending TCP trace %lx, response length %d", existing, existing->resp_len);

            __builtin_memcpy(trace, existing, sizeof(tcp_req_t));
            bpf_probe_read(trace->rbuf, K_TCP_RES_LEN, u_buf);
            bpf_ringbuf_submit(trace, get_flags());
        }
        bpf_map_delete_elem(&ongoing_tcp_req, pid_conn);
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
    } else {
        existing->len += bytes_len;
    }
}

// TAIL_PROTOCOL_TCP
SEC("kprobe/tcp")
int protocol_tcp(void *ctx) {
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

#endif
