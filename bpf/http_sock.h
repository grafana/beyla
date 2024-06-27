#ifndef HTTP_SOCK_HELPERS
#define HTTP_SOCK_HELPERS

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
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

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, call_protocol_info_t);
    __uint(max_entries, 1);
} protocol_mem SEC(".maps");

#define TAIL_PROTOCOL_HTTP  0
#define TAIL_PROTOCOL_HTTP2 1
#define TAIL_PROTOCOL_TCP   3

static __always_inline call_protocol_info_t* protocol_memory() {
    int zero = 0;
    return bpf_map_lookup_elem(&protocol_mem, &zero);
}

static __always_inline void handle_buf_with_connection(pid_connection_info_t *pid_conn, void *u_buf, int bytes_len, u8 ssl, u8 direction, u16 orig_dport) {
    call_protocol_info_t *p_info = protocol_memory();

    if (!p_info) {
        return;
    }
    
    bpf_memcpy(&p_info->pid_conn, pid_conn, sizeof(pid_connection_info_t));
    p_info->ssl = ssl;
    p_info->bytes_len = bytes_len;
    p_info->direction = direction;
    p_info->orig_dport = orig_dport;
    p_info->u_buf = (u64)u_buf;
    bpf_probe_read(p_info->small_buf, MIN_HTTP2_SIZE, u_buf);

    bpf_dbg_printk("buf=[%s], pid=%d, len=%d", p_info->small_buf, pid_conn->pid, bytes_len);

    if (is_http(p_info->small_buf, MIN_HTTP_SIZE, &p_info->packet_type)) {
        bpf_tail_call(p_info, &jump_table, TAIL_PROTOCOL_HTTP);
    } else if (is_http2_or_grpc(p_info->small_buf, MIN_HTTP2_SIZE)) {
        bpf_dbg_printk("Found HTTP2 or gRPC connection");
        u8 is_ssl = ssl;
        bpf_map_update_elem(&ongoing_http2_connections, pid_conn, &is_ssl, BPF_ANY);        
    } else {
        u8 *h2g = bpf_map_lookup_elem(&ongoing_http2_connections, pid_conn);
        if (h2g && *h2g == ssl) {
            bpf_tail_call(p_info, &jump_table, TAIL_PROTOCOL_HTTP2);
        } else { // large request tracking
            http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);

            if (info && still_responding(info)) {
                info->end_monotime_ns = bpf_ktime_get_ns();
            } else if (!info) {
                // SSL requests will see both TCP traffic and text traffic, ignore the TCP if
                // we are processing SSL request. HTTP2 is already checked in handle_buf_with_connection.
                http_info_t *http_info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
                if (!http_info) {
                    bpf_tail_call(p_info, &jump_table, TAIL_PROTOCOL_TCP);
                }
            }
        }
    }
}

#define BUF_COPY_BLOCK_SIZE 16

static __always_inline void read_skb_bytes(const void *skb, u32 offset, unsigned char *buf, const u32 len) {
    u32 max = offset + len;
    int b = 0;
    for (; b < (FULL_BUF_SIZE/BUF_COPY_BLOCK_SIZE); b++) {
        if ((offset + (BUF_COPY_BLOCK_SIZE - 1)) >= max) {
            break;
        }
        bpf_skb_load_bytes(skb, offset, (void *)(&buf[b * BUF_COPY_BLOCK_SIZE]), BUF_COPY_BLOCK_SIZE);
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

    int remaining_to_copy = (remainder < (BUF_COPY_BLOCK_SIZE - 1)) ? remainder : (BUF_COPY_BLOCK_SIZE - 1);
    int space_in_buffer = (len < (b * BUF_COPY_BLOCK_SIZE)) ? 0 : len - (b * BUF_COPY_BLOCK_SIZE);

    if (remaining_to_copy <= space_in_buffer) {
        bpf_skb_load_bytes(skb, offset, (void *)(&buf[b * BUF_COPY_BLOCK_SIZE]), remaining_to_copy);
    }
}

#endif
