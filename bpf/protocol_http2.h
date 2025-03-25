#ifndef PROTOCOL_HTTP2
#define PROTOCOL_HTTP2

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "http2_grpc.h"
#include "http_types.h"
#include "k_tracer_tailcall.h"
#include "pin_internal.h"
#include "protocol_common.h"
#include "ringbuf.h"

// These are bit flags, if you add any use power of 2 values
enum { http2_conn_flag_ssl = WITH_SSL, http2_conn_flag_new = 0x2 };

typedef struct http2_conn_info_data {
    u64 id;
    u8 flags;
} http2_conn_info_data_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t);
    __type(value, http2_conn_info_data_t); // flags and id
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http2_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, http2_conn_stream_t);
    __type(value, http2_grpc_request_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} ongoing_http2_grpc SEC(".maps");

typedef struct grpc_frames_ctx {
    http2_grpc_request_t prev_info;
    u8 has_prev_info;

    int pos; //FIXME should be size_t equivalent
    int saved_buf_pos;
    u32 saved_stream_id;

    u8 found_data_frame;
    u8 iterations;
    u8 terminate_search;

    http2_conn_stream_t stream;

    call_protocol_args_t args;
} grpc_frames_ctx_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, grpc_frames_ctx_t);
    __uint(max_entries, 1);
} grpc_frames_ctx_mem SEC(".maps");

// We want to be able to collect larger amount of data for the grpc/http headers
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, http2_grpc_request_t);
    __uint(max_entries, 1);
} http2_info_mem SEC(".maps");

static __always_inline grpc_frames_ctx_t *grpc_ctx() {
    int zero = 0;
    return bpf_map_lookup_elem(&grpc_frames_ctx_mem, &zero);
}

static __always_inline u8 http2_flag_ssl(u8 flags) {
    return flags & http2_conn_flag_ssl;
}

static __always_inline u8 http2_flag_new(u8 flags) {
    return flags & http2_conn_flag_new;
}

static __always_inline http2_grpc_request_t *empty_http2_info() {
    int zero = 0;
    http2_grpc_request_t *value = bpf_map_lookup_elem(&http2_info_mem, &zero);
    if (value) {
        __builtin_memset(value, 0, sizeof(http2_grpc_request_t));
    }
    return value;
}

static __always_inline u64 uniqueHTTP2ConnId(pid_connection_info_t *p_conn) {
    u64 random_id = (u64)bpf_get_prandom_u32() << 32;

    random_id |= ((u32)p_conn->conn.d_port << 16) | p_conn->conn.s_port;

    return random_id;
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

        h2g_info->new_conn_id = 0;
        http2_conn_info_data_t *h2g =
            bpf_map_lookup_elem(&ongoing_http2_connections, &s_key->pid_conn);
        if (h2g && http2_flag_new(h2g->flags)) {
            h2g_info->new_conn_id = h2g->id;
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

static __always_inline frame_header_t next_frame(const grpc_frames_ctx_t *g_ctx) {
    // read next frame
    const void *offset = (u8 *)g_ctx->args.u_buf + g_ctx->pos;

    frame_header_t header;

    if (bpf_probe_read(&header, sizeof(header), offset) != 0) {
        bpf_dbg_printk("failed to read frame header");
        return header; // the caller will deal with an invalid header
    }

    if (header.length == 0 || header.type > FrameContinuation) {
        return header; // the caller will deal with an invalid header
    }

    header.length = bpf_ntohl(header.length << 8);
    header.stream_id = bpf_ntohl(header.stream_id << 1);

    //bpf_dbg_printk("http2 frame type = %u, len = %u", header.type, header.length);
    //bpf_dbg_printk("http2 frame stream_id = %u, flags = %u", header.stream_id, header.flags);

    return header;
}

static __always_inline void update_prev_info(grpc_frames_ctx_t *g_ctx) {
    if (g_ctx->has_prev_info) {
        return;
    }

    const http2_grpc_request_t *prev_info =
        bpf_map_lookup_elem(&ongoing_http2_grpc, &g_ctx->stream);

    if (prev_info) {
        g_ctx->prev_info = *prev_info;
        g_ctx->has_prev_info = 1;
    }
}

static __always_inline int
handle_headers_frame(void *ctx, grpc_frames_ctx_t *g_ctx, const frame_header_t *frame) {
    g_ctx->stream.stream_id = frame->stream_id;

    // if we don't have prev_info, try looking it up...
    update_prev_info(g_ctx);

    if (g_ctx->has_prev_info) {
        g_ctx->saved_stream_id = g_ctx->stream.stream_id;
        g_ctx->saved_buf_pos = g_ctx->pos;

        if (http_grpc_stream_ended(frame)) {
            bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_end_frame);
            return 0; // normally unrechable
        }
    } else {
        // Not starting new grpc request, found end frame in a start, likely
        // just terminating prev connection
        if (!(is_flags_only_frame(frame) && http_grpc_stream_ended(frame))) {
            bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_start_frame);
            return 0; // normally unrechable
        }
    }

    return 1;
}

static __always_inline void handle_data_frame(void *ctx, grpc_frames_ctx_t *g_ctx) {
    if (!g_ctx->has_prev_info || !g_ctx->saved_stream_id) {
        // we haven't found anything useful...
        return;
    }

    const u8 type = g_ctx->prev_info.type;
    const u8 direction = g_ctx->args.direction;

    if (g_ctx->found_data_frame || ((type == EVENT_HTTP_REQUEST) && (direction == TCP_SEND)) ||
        ((type == EVENT_HTTP_CLIENT) && (direction == TCP_RECV))) {

        g_ctx->stream.pid_conn = g_ctx->args.pid_conn;
        g_ctx->stream.stream_id = g_ctx->saved_stream_id;

        bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_handle_end_frame);
    }
}

// k_tail_protocol_http2_grpc_handle_start_frame
SEC("kprobe/http2")
int beyla_protocol_http2_grpc_handle_start_frame(void *ctx) {
    (void)ctx;

    grpc_frames_ctx_t *g_ctx = grpc_ctx();

    if (!g_ctx) {
        return 0;
    }

    const call_protocol_args_t *args = &g_ctx->args;

    void *offset = (u8 *)args->u_buf + g_ctx->pos;

    http2_grpc_start(
        &g_ctx->stream, offset, args->bytes_len, args->direction, args->ssl, args->orig_dport);

    return 0;
}

// k_tail_protocol_http2_grpc_handle_end_frame
SEC("kprobe/http2")
int beyla_protocol_http2_grpc_handle_end_frame(void *ctx) {
    (void)ctx;

    grpc_frames_ctx_t *g_ctx = grpc_ctx();

    if (!g_ctx) {
        return 0;
    }

    const u8 req_type = request_type_by_direction(g_ctx->args.direction, PACKET_TYPE_RESPONSE);

    if (req_type == g_ctx->prev_info.type) {
        u32 buf_pos = g_ctx->saved_buf_pos;

        bpf_clamp_umax(buf_pos, IO_VEC_MAX_LEN);

        void *offset = (u8 *)g_ctx->args.u_buf + buf_pos;
        http2_grpc_end(&g_ctx->stream, &g_ctx->prev_info, offset);

        bpf_map_delete_elem(&active_ssl_connections, &g_ctx->args.pid_conn);
    } else {
        bpf_dbg_printk("grpc request/response mismatch, req_type %d, prev_info->type %d",
                       req_type,
                       g_ctx->prev_info.type);
        bpf_map_delete_elem(&ongoing_http2_grpc, &g_ctx->stream);
    }

    return 0;
}

// k_tail_protocol_http2_grpc_frames
// this function scans a raw buffer and tries to find GRPC frames on it
// (represented by 'frame_header_t'). We care about 3 kinds of frames: start
// frames, end frames and data frames. Start and end frames are used as anchor
// points to determine the lifespan of a GRPC connection, and the data frames
// are used as a fallback mechanism in case those are found. We use that
// information to evaluate whether the parsed data is potentially a GRPC
// frame, and if so, we ship it to userspace for further processing.
SEC("kprobe/http2")
int beyla_protocol_http2_grpc_frames(void *ctx) {
    const u8 k_max_loop_iterations = 4; // the maximum number of the for loop iterations
    const u8 k_loop_count = 3;          // the number of times we will retry the loop
    const u8 k_iterations = k_max_loop_iterations * k_loop_count;

    grpc_frames_ctx_t *g_ctx = grpc_ctx();

    if (!g_ctx) {
        return 0;
    }

    // this loop will effectively run for k_iterations, split between the
    // unrolled for loop and the tail call (see comment after the loop)
    for (u8 i = 0; i < k_max_loop_iterations; ++i) {
        g_ctx->iterations++;

        if (g_ctx->pos >= g_ctx->args.bytes_len) {
            break;
        }

        const frame_header_t frame = next_frame(g_ctx);

        // if handle_headers_frame returns 0, it means bpf_tail_call has
        // failed and something is very wrong, so we just bail...
        if (is_headers_frame(&frame) && !handle_headers_frame(ctx, g_ctx, &frame)) {
            //bpf_dbg_printk("http2 bpf_tail_call failed");
            return 0;
        }

        if (is_data_frame(&frame)) {
            g_ctx->found_data_frame = 1;
        }

        if (is_invalid_frame(&frame)) {
            g_ctx->terminate_search = 1;
            //bpf_dbg_printk("Invalid frame, terminating search");
            break;
        }

        if (frame.length + k_frame_header_len >= g_ctx->args.bytes_len) {
            g_ctx->terminate_search = 1;
            //bpf_dbg_printk("Frame length bigger than bytes len");
            break;
        }

        if (g_ctx->pos < (g_ctx->args.bytes_len - (frame.length + k_frame_header_len))) {
            g_ctx->pos += (frame.length + k_frame_header_len);
            //bpf_dbg_printk("New buf read g_ctx.pos = %d", g_ctx->pos);
        }
    }

    // this is a weird recursion - we can't loop many times above because the
    // verifier will reject this program as too complex, we don't want to use
    // bpf_loop() as we need to support kernels < 5.17, and finally we don't
    // want to abuse bpf_tail_call as things can get slow (and limited), so we
    // use this mirror-cracking hybrid approach
    if (!g_ctx->terminate_search && g_ctx->iterations < k_iterations) {
        bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_frames);
        return 0; // unreachable, but bail safely if bpf_tail_call fails
    }

    // We only loop N times looking for the stream termination. If the data
    // packed is large we'll miss the frame saying the stream closed. In that
    // case we try this backup path, which will tail call on success.
    handle_data_frame(ctx, g_ctx);

    return 0;
}

// k_tail_protocol_http2
SEC("kprobe/http2")
int beyla_protocol_http2(void *ctx) {
    call_protocol_args_t *args = protocol_args();

    if (!args) {
        return 0;
    }

    grpc_frames_ctx_t *g_ctx = grpc_ctx();

    if (!g_ctx) {
        return 0;
    }

    __builtin_memset(g_ctx, 0, sizeof(*g_ctx));
    g_ctx->args = *args;
    g_ctx->stream.pid_conn = args->pid_conn;

    bpf_tail_call(ctx, &jump_table, k_tail_protocol_http2_grpc_frames);

    return 0;
}

#endif
