#ifndef K_TRACER_HELPERS
#define K_TRACER_HELPERS

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "http_types.h"
#include "ringbuf.h"
#include "pid.h"
#include "trace_common.h"
#include "protocol_common.h"
#include "protocol_http.h"
#include "protocol_http2.h"
#include "protocol_tcp.h"

struct bpf_map_def SEC("maps") jump_table = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 8,
};

#define TAIL_PROTOCOL_HTTP 0
#define TAIL_PROTOCOL_HTTP2 1
#define TAIL_PROTOCOL_TCP 2

static __always_inline void handle_buf_with_args(void *ctx, call_protocol_args_t *args) {
    bpf_probe_read(args->small_buf, MIN_HTTP2_SIZE, (void *)args->u_buf);

    bpf_dbg_printk(
        "buf=[%s], pid=%d, len=%d", args->small_buf, args->pid_conn.pid, args->bytes_len);

    if (is_http(args->small_buf, MIN_HTTP_SIZE, &args->packet_type)) {
        bpf_tail_call(ctx, &jump_table, TAIL_PROTOCOL_HTTP);
    } else if (is_http2_or_grpc(args->small_buf, MIN_HTTP2_SIZE)) {
        bpf_dbg_printk("Found HTTP2 or gRPC connection");
        u8 is_ssl = args->ssl;
        bpf_map_update_elem(&ongoing_http2_connections, &args->pid_conn, &is_ssl, BPF_ANY);
    } else {
        u8 *h2g = bpf_map_lookup_elem(&ongoing_http2_connections, &args->pid_conn);
        if (h2g && *h2g == args->ssl) {
            bpf_tail_call(ctx, &jump_table, TAIL_PROTOCOL_HTTP2);
        } else { // large request tracking
            http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);

            if (info && still_responding(info)) {
                info->end_monotime_ns = bpf_ktime_get_ns();
            } else if (!info) {
                // SSL requests will see both TCP traffic and text traffic, ignore the TCP if
                // we are processing SSL request. HTTP2 is already checked in handle_buf_with_connection.
                http_info_t *http_info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);
                if (!http_info) {
                    bpf_tail_call(ctx, &jump_table, TAIL_PROTOCOL_TCP);
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
