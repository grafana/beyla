#ifndef K_TRACER_HELPERS
#define K_TRACER_HELPERS

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "http_types.h"
#include "k_tracer_tailcall.h"
#include "ringbuf.h"
#include "pid.h"
#include "trace_common.h"
#include "protocol_common.h"
#include "protocol_http.h"
#include "protocol_http2.h"
#include "protocol_tcp.h"
#include "tc_common.h"

typedef struct send_args {
    pid_connection_info_t p_conn;
    u64 size;
    u64 sock_ptr;
} send_args_t;

// Temporary tracking of tcp_recvmsg arguments
typedef struct recv_args {
    u64 sock_ptr; // linux sock or socket address
    u8 iovec_ctx[sizeof(iovec_iter_ctx)];
} recv_args_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, egress_key_t);
    __type(value, msg_buffer_t);
    __uint(max_entries, 1000);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} msg_buffers SEC(".maps");

static __always_inline void handle_buf_with_args(void *ctx, call_protocol_args_t *args) {
    bpf_dbg_printk(
        "buf=[%s], pid=%d, len=%d", args->small_buf, args->pid_conn.pid, args->bytes_len);

    if (is_http(args->small_buf, MIN_HTTP_SIZE, &args->packet_type)) {
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_http);
    } else if (is_http2_or_grpc(args->small_buf, MIN_HTTP2_SIZE)) {
        bpf_dbg_printk("Found HTTP2 or gRPC connection");
        http2_conn_info_data_t data = {
            .id = 0,
            .flags = http2_conn_flag_new,
        };
        data.id = uniqueHTTP2ConnId(&args->pid_conn);
        if (args->ssl) {
            data.flags |= http2_conn_flag_ssl;
        }
        bpf_map_update_elem(&ongoing_http2_connections, &args->pid_conn, &data, BPF_ANY);
    } else {
        http2_conn_info_data_t *h2g =
            bpf_map_lookup_elem(&ongoing_http2_connections, &args->pid_conn);
        if (h2g && (http2_flag_ssl(h2g->flags) == args->ssl)) {
            bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2);
        } else { // large request tracking
            http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);

            if (info) {
                // Still reading checks if we are processing buffers of a HTTP request
                // that has started, but we haven't seen a response yet.
                if (still_reading(info)) {
                    // Packets are split into chunks if Beyla injected the Traceparent
                    // Make sure you look for split packets containing the real Traceparent.
                    // Essentially, when a packet is extended by our sock_msg program and
                    // passed down another service, the receiving side may reassemble the
                    // packets into one buffer or not. If they are reassembled, then the
                    // call to bpf_tail_call(ctx, &jump_table, k_tail_protocol_http); will
                    // scan for the incoming 'Traceparent' header. If they are not reassembled
                    // we'll see something like this:
                    // [before the injected header],[70 bytes for 'Traceparent...'],[the rest].
                    if (is_traceparent(args->small_buf)) {
                        unsigned char *buf = tp_char_buf();
                        if (buf) {
                            bpf_probe_read(buf, EXTEND_SIZE, (u8 *)args->u_buf);
                            bpf_dbg_printk("Found traceparent %s", buf);
                            unsigned char *t_id = extract_trace_id(buf);
                            unsigned char *s_id = extract_span_id(buf);
                            unsigned char *f_id = extract_flags(buf);

                            decode_hex(info->tp.trace_id, t_id, TRACE_ID_CHAR_LEN);
                            decode_hex((unsigned char *)&info->tp.flags, f_id, FLAGS_CHAR_LEN);
                            decode_hex(info->tp.parent_id, s_id, SPAN_ID_CHAR_LEN);

                            trace_key_t t_key = {0};
                            task_tid(&t_key.p_key);
                            t_key.extra_id = extra_runtime_id();

                            tp_info_pid_t *existing = bpf_map_lookup_elem(&server_traces, &t_key);
                            if (existing) {
                                __builtin_memcpy(&existing->tp, &info->tp, sizeof(tp_info_t));
                                set_trace_info_for_connection(
                                    &args->pid_conn.conn, TRACE_TYPE_SERVER, existing);
                            } else {
                                bpf_dbg_printk("Didn't find existing trace, this might be a bug!");
                            }
                        }
                    }
                } else if (still_responding(info)) {
                    info->end_monotime_ns = bpf_ktime_get_ns();
                }
            } else if (!info) {
                // SSL requests will see both TCP traffic and text traffic, ignore the TCP if
                // we are processing SSL request. HTTP2 is already checked in handle_buf_with_connection.
                http_info_t *http_info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);
                if (!http_info) {
                    bpf_tail_call(ctx, &jump_table, k_tail_protocol_tcp);
                }
            }
        }
    }
}

static __always_inline call_protocol_args_t *
make_protocol_args(void *u_buf, int bytes_len, u8 ssl, u8 direction, u16 orig_dport) {
    call_protocol_args_t *args = protocol_args();

    if (!args) {
        return 0;
    }

    args->ssl = ssl;
    args->bytes_len = bytes_len;
    args->direction = direction;
    args->orig_dport = orig_dport;
    args->u_buf = (u64)u_buf;

    return args;
}

static __always_inline void handle_buf_with_connection(void *ctx,
                                                       pid_connection_info_t *pid_conn,
                                                       void *u_buf,
                                                       int bytes_len,
                                                       u8 ssl,
                                                       u8 direction,
                                                       u16 orig_dport) {
    call_protocol_args_t *args = make_protocol_args(u_buf, bytes_len, ssl, direction, orig_dport);

    if (!args) {
        return;
    }

    __builtin_memcpy(&args->pid_conn, pid_conn, sizeof(pid_connection_info_t));
    bpf_probe_read(args->small_buf, MIN_HTTP2_SIZE, (void *)args->u_buf);
    handle_buf_with_args(ctx, args);
}

#define BUF_COPY_BLOCK_SIZE 16

static __always_inline void
read_skb_bytes(const void *skb, u32 offset, unsigned char *buf, const u32 len) {
    u32 max = offset + len;
    int b = 0;
    for (; b < (FULL_BUF_SIZE / BUF_COPY_BLOCK_SIZE); b++) {
        if ((offset + (BUF_COPY_BLOCK_SIZE - 1)) >= max) {
            break;
        }
        bpf_skb_load_bytes(
            skb, offset, (void *)(&buf[b * BUF_COPY_BLOCK_SIZE]), BUF_COPY_BLOCK_SIZE);
        offset += BUF_COPY_BLOCK_SIZE;
    }

    if ((b * BUF_COPY_BLOCK_SIZE) >= len) {
        return;
    }

    // This code is messy to make sure the eBPF verifier is happy. I had to cast to signed 64bit.
    s64 remainder = (s64)max - (s64)offset;

    if (remainder <= 0) {
        return;
    }

    int remaining_to_copy =
        (remainder < (BUF_COPY_BLOCK_SIZE - 1)) ? remainder : (BUF_COPY_BLOCK_SIZE - 1);
    int space_in_buffer = (len < (b * BUF_COPY_BLOCK_SIZE)) ? 0 : len - (b * BUF_COPY_BLOCK_SIZE);

    if (remaining_to_copy <= space_in_buffer) {
        bpf_skb_load_bytes(skb, offset, (void *)(&buf[b * BUF_COPY_BLOCK_SIZE]), remaining_to_copy);
    }
}

#endif
