#ifndef PROTOCOL_HTTP2
#define PROTOCOL_HTTP2

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "http_types.h"
#include "ringbuf.h"
#include "protocol_common.h"
#include "http2_grpc.h"
#include "pin_internal.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t);
    __type(value, u8); // ssl or not
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http2_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, http2_conn_stream_t);
    __type(value, http2_grpc_request_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} ongoing_http2_grpc SEC(".maps");

// We want to be able to collect larger amount of data for the grpc/http headers
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, http2_grpc_request_t);
    __uint(max_entries, 1);
} http2_info_mem SEC(".maps");

static __always_inline http2_grpc_request_t *empty_http2_info() {
    int zero = 0;
    http2_grpc_request_t *value = bpf_map_lookup_elem(&http2_info_mem, &zero);
    if (value) {
        __builtin_memset(value, 0, sizeof(http2_grpc_request_t));
    }
    return value;
}

static __always_inline void http2_grpc_start(
    http2_conn_stream_t *s_key, void *u_buf, int len, u8 direction, u8 ssl, u16 orig_dport) {
    http2_grpc_request_t *existing = bpf_map_lookup_elem(&ongoing_http2_grpc, s_key);
    if (existing) {
        bpf_dbg_printk("already found existing grpcstart, ignoring this exchange");
        return;
    }
    http2_grpc_request_t *h2g_info = empty_http2_info();
    bpf_dbg_printk("http2/grpc start direction=%d stream=%d", direction, s_key->stream_id);
    //dbg_print_http_connection_info(&s_key->pid_conn.conn); // commented out since GitHub CI doesn't like this call
    if (h2g_info) {
        http_connection_metadata_t *meta =
            connection_meta_by_direction(&s_key->pid_conn, direction, PACKET_TYPE_REQUEST);
        if (!meta) {
            bpf_dbg_printk("Can't get meta memory or connection not found");
            return;
        }

        h2g_info->flags = EVENT_K_HTTP2_REQUEST;
        h2g_info->start_monotime_ns = bpf_ktime_get_ns();
        h2g_info->len = len;
        h2g_info->ssl = ssl;
        h2g_info->conn_info = s_key->pid_conn.conn;
        if (meta) { // keep verifier happy
            h2g_info->pid = meta->pid;
            h2g_info->type = meta->type;
        }
        fixup_connection_info(
            &h2g_info->conn_info, h2g_info->type == EVENT_HTTP_CLIENT, orig_dport);
        bpf_probe_read(h2g_info->data, KPROBES_HTTP2_BUF_SIZE, u_buf);

        bpf_map_update_elem(&ongoing_http2_grpc, s_key, h2g_info, BPF_ANY);
    }
}

static __always_inline void
http2_grpc_end(http2_conn_stream_t *stream, http2_grpc_request_t *prev_info, void *u_buf) {
    bpf_dbg_printk("http2/grpc end prev_info=%llx", prev_info);
    if (prev_info) {
        prev_info->end_monotime_ns = bpf_ktime_get_ns();
        bpf_dbg_printk("stream_id = %d", stream->stream_id);
        //dbg_print_http_connection_info(&stream->pid_conn.conn); // commented out since GitHub CI doesn't like this call

        http2_grpc_request_t *trace = bpf_ringbuf_reserve(&events, sizeof(http2_grpc_request_t), 0);
        if (trace) {
            bpf_probe_read(prev_info->ret_data, KPROBES_HTTP2_RET_BUF_SIZE, u_buf);
            __builtin_memcpy(trace, prev_info, sizeof(http2_grpc_request_t));
            bpf_ringbuf_submit(trace, get_flags());
        }
    }

    bpf_map_delete_elem(&ongoing_http2_grpc, stream);
}

static __always_inline void process_http2_grpc_frames(pid_connection_info_t *pid_conn,
                                                      void *u_buf,
                                                      int bytes_len,
                                                      u8 direction,
                                                      u8 ssl,
                                                      u16 orig_dport) {
    int pos = 0;
    u8 found_start_frame = 0;
    u8 found_end_frame = 0;

    http2_grpc_request_t *prev_info = 0;
    u32 saved_stream_id = 0;
    int saved_buf_pos = 0;
    u8 found_data_frame = 0;
    http2_conn_stream_t stream = {0};

    unsigned char frame_buf[FRAME_HEADER_LEN];
    frame_header_t frame = {0};

    for (int i = 0; i < 8; i++) {
        if (pos >= bytes_len) {
            break;
        }

        bpf_probe_read(&frame_buf, FRAME_HEADER_LEN, (void *)((u8 *)u_buf + pos));
        read_http2_grpc_frame_header(&frame, frame_buf, FRAME_HEADER_LEN);
        //bpf_dbg_printk("http2 frame type = %d, len = %d, stream_id = %d, flags = %d", frame.type, frame.length, frame.stream_id, frame.flags);

        if (is_headers_frame(&frame)) {
            stream.pid_conn = *pid_conn;
            stream.stream_id = frame.stream_id;
            if (!prev_info) {
                prev_info = bpf_map_lookup_elem(&ongoing_http2_grpc, &stream);
            }

            if (prev_info) {
                saved_stream_id = stream.stream_id;
                saved_buf_pos = pos;
                if (http_grpc_stream_ended(&frame)) {
                    found_end_frame = 1;
                    break;
                }
            } else {
                // Not starting new grpc request, found end frame in a start, likely just terminating prev connection
                if (!(is_flags_only_frame(&frame) && http_grpc_stream_ended(&frame))) {
                    found_start_frame = 1;
                    break;
                }
            }
        }

        if (is_data_frame(&frame)) {
            found_data_frame = 1;
        }

        if (is_invalid_frame(&frame)) {
            //bpf_dbg_printk("Invalid frame, terminating search");
            break;
        }

        if (frame.length + FRAME_HEADER_LEN >= bytes_len) {
            //bpf_dbg_printk("Frame length bigger than bytes len");
            break;
        }

        if (pos < (bytes_len - (frame.length + FRAME_HEADER_LEN))) {
            pos += (frame.length + FRAME_HEADER_LEN);
            //bpf_dbg_printk("New buf read pos = %d", pos);
        }
    }

    if (found_start_frame) {
        http2_grpc_start(
            &stream, (void *)((u8 *)u_buf + pos), bytes_len, direction, ssl, orig_dport);
    } else {
        // We only loop 6 times looking for the stream termination. If the data packed is large we'll miss the
        // frame saying the stream closed. In that case we try this backup path.
        if (!found_end_frame && prev_info && saved_stream_id) {
            if (found_data_frame ||
                ((prev_info->type == EVENT_HTTP_REQUEST) && (direction == TCP_SEND)) ||
                ((prev_info->type == EVENT_HTTP_CLIENT) && (direction == TCP_RECV))) {
                stream.pid_conn = *pid_conn;
                stream.stream_id = saved_stream_id;
                found_end_frame = 1;
            }
        }
        if (found_end_frame) {
            u8 req_type = request_type_by_direction(direction, PACKET_TYPE_RESPONSE);
            if (prev_info) {
                if (req_type == prev_info->type) {
                    u32 buf_pos = saved_buf_pos;
                    bpf_clamp_umax(buf_pos, IO_VEC_MAX_LEN);
                    http2_grpc_end(&stream, prev_info, (void *)((u8 *)u_buf + buf_pos));
                    bpf_map_delete_elem(&active_ssl_connections, pid_conn);
                } else {
                    bpf_dbg_printk(
                        "grpc request/response mismatch, req_type %d, prev_info->type %d",
                        req_type,
                        prev_info->type);
                    bpf_map_delete_elem(&ongoing_http2_grpc, &stream);
                }
            }
        }
    }
}

// TAIL_PROTOCOL_HTTP2
SEC("kprobe/http2")
int protocol_http2(void *ctx) {
    call_protocol_args_t *args = protocol_args();

    if (!args) {
        return 0;
    }

    process_http2_grpc_frames(&args->pid_conn,
                              (void *)args->u_buf,
                              args->bytes_len,
                              args->direction,
                              args->ssl,
                              args->orig_dport);

    return 0;
}

#endif
