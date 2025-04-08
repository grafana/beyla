// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <bpfcore/utils.h>

#include <common/ringbuf.h>

#include <gotracer/go_byte_arr.h>
#include <gotracer/go_common.h>
#include <gotracer/go_str.h>
#include <gotracer/hpack.h>

#include <logger/bpf_dbg.h>

#include <pid/pid_helpers.h>

typedef struct grpc_srv_func_invocation {
    u64 start_monotime_ns;
    u64 stream;
    u64 st;
    tp_info_t tp;
} grpc_srv_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, u16);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_request_status SEC(".maps");

typedef struct grpc_client_func_invocation {
    u64 start_monotime_ns;
    u64 cc;
    u64 method;
    u64 method_len;
    tp_info_t tp;
    u64 flags;
} grpc_client_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, grpc_client_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_client_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, grpc_srv_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_server_requests SEC(".maps");

// Context propagation
// TODO: use go_addr_key_t as key
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);                             // key: stream id
    __type(value, grpc_client_func_invocation_t); // stored info for the client request
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_streams SEC(".maps");

// TODO: use go_addr_key_t as key
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, grpc_client_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_header_writes SEC(".maps");

#define TRANSPORT_HTTP2 1
#define TRANSPORT_HANDLER 2

#define OPTIMISTIC_GRPC_ENCODED_HEADER_LEN                                                         \
    49 // 1 + 1 + 8 + 1 +~ 38 = type byte + hpack_len_as_byte("traceparent") + strlen(hpack("traceparent")) + len_as_byte(38) + hpack(generated tracepanent id)

SEC("uprobe/server_handleStream")
int beyla_uprobe_server_handleStream(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/server_handleStream === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    void *stream_ptr = GO_PARAM4(ctx);
    void *stream_stream_ptr = stream_ptr;
    off_table_t *ot = get_offsets_table();

    u64 st_offset = go_offset_of(ot, (go_offset){.v = _grpc_stream_st_ptr_pos});

    u64 new_handle_stream = go_offset_of(ot, (go_offset){.v = _grpc_one_six_nine});
    bpf_dbg_printk("stream pointer %llx, new_handle_stream %d", stream_ptr, new_handle_stream);
    if (new_handle_stream == 1) {
        // Read the embedded object ptr
        bpf_probe_read(
            &stream_stream_ptr,
            sizeof(stream_stream_ptr),
            (void *)(stream_ptr + go_offset_of(ot, (go_offset){.v = _grpc_server_stream_stream})));

        bpf_dbg_printk("new stream pointer %llx", stream_stream_ptr);
        if (!stream_stream_ptr) {
            bpf_dbg_printk("Error loading embedded server stream pointer from %llx", stream_ptr);
            return 0;
        }
        st_offset = go_offset_of(ot, (go_offset){.v = _grpc_server_stream_st_ptr_pos});
    }

    grpc_srv_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .stream = (u64)stream_stream_ptr,
        .st = 0,
        .tp = {0},
    };

    if (stream_ptr) {
        void *st_ptr = 0;
        void *tp_ptr = 0;
        // Read the embedded object ptr
        bpf_probe_read(&st_ptr, sizeof(st_ptr), (void *)(stream_ptr + st_offset + sizeof(void *)));

        bpf_dbg_printk("st_ptr %llx", st_ptr);
        invocation.st = (u64)st_ptr;
        if (st_ptr) {
            grpc_transports_t *t = bpf_map_lookup_elem(&ongoing_grpc_transports, &st_ptr);

            bpf_dbg_printk("found t %llx", t);
            if (t) {
                bpf_dbg_printk("reading the traceparent from frame headers");
                if (valid_trace(t->tp.trace_id)) {
                    tp_ptr = &t->tp;
                }
            }
        }

        server_trace_parent(goroutine_addr, &invocation.tp, tp_ptr);
    }

    if (bpf_map_update_elem(&ongoing_grpc_server_requests, &g_key, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update grpc map element");
    }

    return 0;
}

// Handles finding the connection information for http2 servers in grpc
SEC("uprobe/http2Server_operateHeaders")
int beyla_uprobe_http2Server_operateHeaders(struct pt_regs *ctx) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    void *tr = GO_PARAM1(ctx);
    void *frame = GO_PARAM2(ctx);
    off_table_t *ot = get_offsets_table();

    u64 new_offset_version = go_offset_of(ot, (go_offset){.v = _grpc_one_six_zero});

    // After grpc version 1.60, they added extra context argument to the
    // function call, which adds two extra arguments.
    if (new_offset_version) {
        frame = GO_PARAM4(ctx);
    }

    bpf_dbg_printk("=== uprobe/GRPC http2Server_operateHeaders tr %llx goroutine %lx, new %d === ",
                   tr,
                   goroutine_addr,
                   new_offset_version);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    grpc_transports_t t = {
        .type = TRANSPORT_HTTP2,
        .conn = {0},
        .tp = {0},
    };

    process_meta_frame_headers(frame, &t.tp);

    bpf_map_update_elem(&ongoing_grpc_operate_headers, &g_key, &tr, BPF_ANY);
    bpf_map_update_elem(&ongoing_grpc_transports, &tr, &t, BPF_ANY);

    return 0;
}

// Handles finding the connection information for grpc ServeHTTP
SEC("uprobe/serverHandlerTransport_HandleStreams")
int beyla_uprobe_server_handler_transport_handle_streams(struct pt_regs *ctx) {
    void *tr = GO_PARAM1(ctx);
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_printk("=== uprobe/serverHandlerTransport_HandleStreams tr %llx goroutine %lx === ",
               tr,
               goroutine_addr);

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    void *parent_go = (void *)find_parent_goroutine(&g_key);
    if (parent_go) {
        bpf_dbg_printk("found parent goroutine for transport handler [%llx]", parent_go);
        go_addr_key_t p_key = {};
        go_addr_key_from_id(&p_key, parent_go);
        connection_info_t *conn = bpf_map_lookup_elem(&ongoing_server_connections, &p_key);
        bpf_dbg_printk("conn %llx", conn);
        if (conn) {
            grpc_transports_t t = {
                .type = TRANSPORT_HANDLER,
            };
            __builtin_memcpy(&t.conn, conn, sizeof(connection_info_t));

            bpf_map_update_elem(&ongoing_grpc_transports, &tr, &t, BPF_ANY);
        }
    }

    return 0;
}

SEC("uprobe/server_handleStream")
int beyla_uprobe_server_handleStream_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/server_handleStream return === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    grpc_srv_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_grpc_server_requests, &g_key);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read grpc invocation metadata");
        goto done;
    }

    u16 *status_ptr = bpf_map_lookup_elem(&ongoing_grpc_request_status, &g_key);
    u16 status = 0;
    if (status_ptr != NULL) {
        bpf_dbg_printk("can't read grpc invocation status");
        status = *status_ptr;
    }

    void *stream_ptr = (void *)invocation->stream;
    void *st_ptr = (void *)invocation->st;
    u64 grpc_stream_method_ptr_pos =
        go_offset_of(ot, (go_offset){.v = _grpc_stream_method_ptr_pos});
    bpf_dbg_printk("stream_ptr %lx, st_ptr %lx, method pos %lx",
                   stream_ptr,
                   st_ptr,
                   grpc_stream_method_ptr_pos);

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        goto done;
    }
    task_pid(&trace->pid);
    trace->type = EVENT_GRPC_REQUEST;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->status = status;
    trace->content_length = 0;
    trace->method[0] = '\0';
    trace->host[0] = '\0';
    trace->scheme[0] = '\0';
    trace->go_start_monotime_ns = invocation->start_monotime_ns;
    bpf_map_delete_elem(&ongoing_goroutines, &g_key);

    // Get method from transport.Stream.Method
    if (!read_go_str("grpc method",
                     stream_ptr,
                     grpc_stream_method_ptr_pos,
                     &trace->path,
                     sizeof(trace->path))) {
        bpf_dbg_printk("can't read grpc transport.Stream.Method");
        bpf_ringbuf_discard(trace, 0);
        goto done;
    }

    u8 found_conn = 0;
    if (st_ptr) {
        grpc_transports_t *t = bpf_map_lookup_elem(&ongoing_grpc_transports, &st_ptr);

        bpf_dbg_printk("found t %llx", t);
        if (t) {
            bpf_dbg_printk("setting up connection info from grpc handler");
            __builtin_memcpy(&trace->conn, &t->conn, sizeof(connection_info_t));
            found_conn = 1;
        }
    }

    if (!found_conn) {
        bpf_dbg_printk("can't find connection info for st_ptr %llx", st_ptr);
        __builtin_memset(&trace->conn, 0, sizeof(connection_info_t));
    }

    // Server connections have port order reversed from what we want
    swap_connection_info_order(&trace->conn);
    trace->tp = invocation->tp;
    trace->end_monotime_ns = bpf_ktime_get_ns();
    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

done:
    bpf_map_delete_elem(&ongoing_grpc_server_requests, &g_key);
    bpf_map_delete_elem(&ongoing_grpc_request_status, &g_key);
    bpf_map_delete_elem(&go_trace_map, &g_key);

    return 0;
}

SEC("uprobe/transport_writeStatus")
int beyla_uprobe_transport_writeStatus(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/transport_writeStatus === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    void *status_ptr = GO_PARAM3(ctx);
    bpf_dbg_printk("status_ptr %lx", status_ptr);

    if (status_ptr != NULL) {
        void *s_ptr;
        bpf_probe_read(
            &s_ptr,
            sizeof(s_ptr),
            (void *)(status_ptr + go_offset_of(ot, (go_offset){.v = _grpc_status_s_pos})));

        bpf_dbg_printk("s_ptr %lx", s_ptr);

        if (s_ptr != NULL) {
            u16 status = -1;
            bpf_probe_read(
                &status,
                sizeof(status),
                (void *)(s_ptr + go_offset_of(ot, (go_offset){.v = _grpc_status_code_ptr_pos})));
            bpf_dbg_printk("status code %d", status);
            bpf_map_update_elem(&ongoing_grpc_request_status, &g_key, &status, BPF_ANY);
        }
    }

    return 0;
}

/* GRPC client */
static __always_inline void clientConnStart(
    void *goroutine_addr, void *cc_ptr, void *ctx_ptr, void *method_ptr, void *method_len) {
    grpc_client_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .cc = (u64)cc_ptr,
        .method = (u64)method_ptr,
        .method_len = (u64)method_len,
        .tp = {0},
        .flags = 0,
    };
    off_table_t *ot = get_offsets_table();
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    if (ctx_ptr) {
        void *val_ptr = 0;
        // Read the embedded val object ptr from ctx if there's one
        bpf_probe_read(&val_ptr,
                       sizeof(val_ptr),
                       (void *)(ctx_ptr +
                                go_offset_of(ot, (go_offset){.v = _value_context_val_ptr_pos}) +
                                sizeof(void *)));

        invocation.flags = client_trace_parent(goroutine_addr, &invocation.tp);
    } else {
        // it's OK sending empty tp for a client, the userspace id generator will make random trace_id, span_id
        bpf_dbg_printk("No ctx_ptr %llx", ctx_ptr);
    }

    // Write event
    if (bpf_map_update_elem(&ongoing_grpc_client_requests, &g_key, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update grpc client map element");
    }
}

SEC("uprobe/ClientConn_Invoke")
int beyla_uprobe_ClientConn_Invoke(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc ClientConn.Invoke === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *cc_ptr = GO_PARAM1(ctx);
    void *ctx_ptr = GO_PARAM3(ctx);
    void *method_ptr = GO_PARAM4(ctx);
    void *method_len = GO_PARAM5(ctx);

    clientConnStart(goroutine_addr, cc_ptr, ctx_ptr, method_ptr, method_len);

    return 0;
}

// Same as ClientConn_Invoke, registers for the method are offset by one
SEC("uprobe/ClientConn_NewStream")
int beyla_uprobe_ClientConn_NewStream(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc ClientConn.NewStream === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *cc_ptr = GO_PARAM1(ctx);
    void *ctx_ptr = GO_PARAM3(ctx);
    void *method_ptr = GO_PARAM5(ctx);
    void *method_len = GO_PARAM6(ctx);

    clientConnStart(goroutine_addr, cc_ptr, ctx_ptr, method_ptr, method_len);

    return 0;
}

static __always_inline int grpc_connect_done(struct pt_regs *ctx, void *err) {
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    grpc_client_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_grpc_client_requests, &g_key);

    if (invocation == NULL) {
        bpf_dbg_printk("can't read grpc client invocation metadata");
        goto done;
    }

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        goto done;
    }

    task_pid(&trace->pid);
    trace->type = EVENT_GRPC_CLIENT;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->go_start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();
    trace->content_length = 0;
    trace->method[0] = '\0';
    trace->host[0] = '\0';
    trace->scheme[0] = '\0';

    // Read arguments from the original set of registers

    // Get client request value pointers
    void *method_ptr = (void *)invocation->method;
    void *method_len = (void *)invocation->method_len;

    bpf_dbg_printk("method ptr = %lx, method_len = %d", method_ptr, method_len);

    // Get method from the incoming call arguments
    if (!read_go_str_n("method", method_ptr, (u64)method_len, &trace->path, sizeof(trace->path))) {
        bpf_dbg_printk("can't read grpc client method");
        bpf_ringbuf_discard(trace, 0);
        goto done;
    }

    connection_info_t *info = bpf_map_lookup_elem(&ongoing_client_connections, &g_key);

    if (info) {
        __builtin_memcpy(&trace->conn, info, sizeof(connection_info_t));
    } else {
        __builtin_memset(&trace->conn, 0, sizeof(connection_info_t));
    }

    trace->tp = invocation->tp;

    trace->status =
        (err)
            ? 2
            : 0; // Getting the gRPC client status is complex, if there's an error we set Code.Unknown = 2

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

done:
    bpf_map_delete_elem(&ongoing_grpc_client_requests, &g_key);
    return 0;
}

// Same as ClientConn_Invoke, registers for the method are offset by one
SEC("uprobe/ClientConn_NewStream")
int beyla_uprobe_ClientConn_NewStream_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc ClientConn.NewStream return === ");

    void *stream = GO_PARAM1(ctx);

    if (!stream) {
        return grpc_connect_done(ctx, (void *)1);
    }

    return 0;
}

SEC("uprobe/ClientConn_Close")
int beyla_uprobe_ClientConn_Close(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc ClientConn.Close === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    bpf_map_delete_elem(&ongoing_grpc_client_requests, &g_key);

    return 0;
}

SEC("uprobe/ClientConn_Invoke")
int beyla_uprobe_ClientConn_Invoke_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc ClientConn.Invoke return === ");

    void *err = GO_PARAM1(ctx);

    if (err) {
        return grpc_connect_done(ctx, err);
    }

    return 0;
}

// google.golang.org/grpc.(*clientStream).RecvMsg
SEC("uprobe/clientStream_RecvMsg")
int beyla_uprobe_clientStream_RecvMsg_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc clientStream.RecvMsg return === ");
    void *err = (void *)GO_PARAM1(ctx);
    return grpc_connect_done(ctx, err);
}

// The gRPC client stream is written on another goroutine in transport loopyWriter (controlbuf.go).
// We extract the stream ID when it's just created and make a mapping of it to our goroutine that's executing ClientConn.Invoke.
SEC("uprobe/transport_http2Client_NewStream")
int beyla_uprobe_transport_http2Client_NewStream(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc transport.(*http2Client).NewStream === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    void *t_ptr = GO_PARAM1(ctx);
    off_table_t *ot = get_offsets_table();
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    u64 grpc_t_conn_pos = go_offset_of(ot, (go_offset){.v = _grpc_t_scheme_pos});
    bpf_dbg_printk(
        "goroutine_addr %lx, t_ptr %llx, t.conn_pos %x", goroutine_addr, t_ptr, grpc_t_conn_pos);

    if (t_ptr) {
        void *conn_ptr = t_ptr + go_offset_of(ot, (go_offset){.v = _grpc_t_conn_pos}) + 8;
        u8 buf[16];
        u64 is_secure = 0;

        void *s_ptr = 0;
        buf[0] = 0;
        bpf_probe_read(&s_ptr, sizeof(s_ptr), (void *)(t_ptr + grpc_t_conn_pos));
        bpf_probe_read(buf, sizeof(buf), s_ptr);

        //bpf_dbg_printk("scheme %s", buf);

        if (buf[0] == 'h' && buf[1] == 't' && buf[2] == 't' && buf[3] == 'p' && buf[4] == 's') {
            is_secure = 1;
        }

        if (is_secure) {
            // double wrapped in grpc
            conn_ptr = unwrap_tls_conn_info(conn_ptr, (void *)is_secure);
            conn_ptr = unwrap_tls_conn_info(conn_ptr, (void *)is_secure);
        }
        bpf_dbg_printk("conn_ptr %llx is_secure %lld", conn_ptr, is_secure);
        if (conn_ptr) {
            void *conn_conn_ptr = 0;
            bpf_probe_read(&conn_conn_ptr, sizeof(conn_conn_ptr), conn_ptr);
            bpf_dbg_printk("conn_conn_ptr %llx", conn_conn_ptr);
            if (conn_conn_ptr) {
                connection_info_t conn = {0};
                u8 ok = get_conn_info(conn_conn_ptr, &conn);
                if (ok) {
                    bpf_map_update_elem(&ongoing_client_connections, &g_key, &conn, BPF_ANY);
                }
            }
        }

#ifndef NO_HEADER_PROPAGATION
        u32 next_id = 0;
        // Read the next stream id from the httpClient
        bpf_probe_read(
            &next_id,
            sizeof(next_id),
            (void *)(t_ptr + go_offset_of(ot, (go_offset){.v = _http2_client_next_id_pos})));

        bpf_dbg_printk("next_id %d", next_id);

        grpc_client_func_invocation_t *invocation =
            bpf_map_lookup_elem(&ongoing_grpc_client_requests, &g_key);

        if (invocation) {
            grpc_client_func_invocation_t inv_save = *invocation;
            // This map is an LRU map, we can't be sure that all created streams are going to be
            // seen later by writeHeader to clean up this mapping.
            bpf_map_update_elem(&ongoing_streams, &next_id, &inv_save, BPF_ANY);
        } else {
            bpf_dbg_printk("Couldn't find invocation metadata for goroutine %lx", goroutine_addr);
        }
#endif
    }

    return 0;
}

#ifndef NO_HEADER_PROPAGATION
typedef struct grpc_framer_func_invocation {
    u64 framer_ptr;
    tp_info_t tp;
    s64 offset;
} grpc_framer_func_invocation_t;

#define MAX_W_PTR_OFFSET 1024

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: go routine doing framer write headers
    __type(
        value,
        grpc_framer_func_invocation_t); // the goroutine of the round trip request, which is the key for our traceparent info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} grpc_framer_invocation_map SEC(".maps");

SEC("uprobe/grpcFramerWriteHeaders")
int beyla_uprobe_grpcFramerWriteHeaders(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc Framer writeHeaders === ");

    void *framer = GO_PARAM1(ctx);
    u64 stream_id = (u64)GO_PARAM2(ctx);

    off_table_t *ot = get_offsets_table();
    u64 framer_w_pos = go_offset_of(ot, (go_offset){.v = _framer_w_pos});

    if (framer_w_pos == -1) {
        bpf_dbg_printk("framer w not found");
        return 0;
    }

    bpf_dbg_printk(
        "framer=%llx, stream_id=%lld, framer_w_pos %llx", framer, ((u64)stream_id), framer_w_pos);

    u32 stream_lookup = (u32)stream_id;

    grpc_client_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_streams, &stream_lookup);

    if (invocation) {
        bpf_dbg_printk("Found invocation info %llx", invocation);
        void *goroutine_addr = GOROUTINE_PTR(ctx);
        go_addr_key_t g_key = {};
        go_addr_key_from_id(&g_key, goroutine_addr);

        void *w_ptr = (void *)(framer + framer_w_pos + 16);
        bpf_probe_read(&w_ptr, sizeof(w_ptr), (void *)(framer + framer_w_pos + 8));

        if (w_ptr) {
            s64 offset;
            bpf_probe_read(
                &offset,
                sizeof(offset),
                (void *)(w_ptr + go_offset_of(
                                     ot, (go_offset){.v = _grpc_transport_buf_writer_offset_pos})));

            bpf_dbg_printk("Found initial data offset %d", offset);

            // The offset will be 0 on first connection through the stream and 9 on subsequent.
            // If we read some very large offset, we don't do anything since it might be a situation
            // we can't handle
            if (offset < MAX_W_PTR_OFFSET) {
                grpc_framer_func_invocation_t f_info = {
                    .tp = invocation->tp,
                    .framer_ptr = (u64)framer,
                    .offset = offset,
                };

                bpf_map_update_elem(&grpc_framer_invocation_map, &g_key, &f_info, BPF_ANY);
            } else {
                bpf_dbg_printk("Offset too large, ignoring...");
            }
        }
    }

    bpf_map_delete_elem(&ongoing_streams, &stream_id);
    return 0;
}
#else
SEC("uprobe/grpcFramerWriteHeaders")
int beyla_uprobe_grpcFramerWriteHeaders(struct pt_regs *ctx) {
    return 0;
}
#endif

#ifndef NO_HEADER_PROPAGATION
#define HTTP2_ENCODED_HEADER_LEN                                                                   \
    66 // 1 + 1 + 8 + 1 + 55 = type byte + hpack_len_as_byte("traceparent") + strlen(hpack("traceparent")) + len_as_byte(55) + generated traceparent id

SEC("uprobe/grpcFramerWriteHeaders_returns")
int beyla_uprobe_grpcFramerWriteHeaders_returns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc Framer writeHeaders returns === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    off_table_t *ot = get_offsets_table();
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    grpc_framer_func_invocation_t *f_info =
        bpf_map_lookup_elem(&grpc_framer_invocation_map, &g_key);

    if (f_info) {
        void *w_ptr =
            (void *)(f_info->framer_ptr + go_offset_of(ot, (go_offset){.v = _framer_w_pos}) + 16);
        bpf_probe_read(
            &w_ptr,
            sizeof(w_ptr),
            (void *)(f_info->framer_ptr + go_offset_of(ot, (go_offset){.v = _framer_w_pos}) + 8));

        if (w_ptr) {
            void *buf_arr = 0;
            s64 n = 0;
            s64 cap = 0;
            u64 off = f_info->offset;

            bpf_probe_read(
                &buf_arr,
                sizeof(buf_arr),
                (void
                     *)(w_ptr +
                        go_offset_of(
                            ot,
                            (go_offset){
                                .v =
                                    _grpc_transport_buf_writer_buf_pos}))); // the buffer is the first field
            bpf_probe_read(
                &n,
                sizeof(n),
                (void *)(w_ptr + go_offset_of(
                                     ot, (go_offset){.v = _grpc_transport_buf_writer_offset_pos})));
            bpf_probe_read(
                &cap,
                sizeof(cap),
                (void *)(w_ptr +
                         go_offset_of(ot, (go_offset){.v = _grpc_transport_buf_writer_offset_pos}) +
                         16)); // the offset of the capacity is 2 * 8 bytes from the buf

            bpf_clamp_umax(off, MAX_W_PTR_OFFSET);

            //bpf_dbg_printk("Found f_info, this is the place to write to w = %llx, buf=%llx, n=%lld, size=%lld", w_ptr, buf_arr, n, cap);
            if (buf_arr && n < (cap - HTTP2_ENCODED_HEADER_LEN)) {
                uint8_t tp_str[TP_MAX_VAL_LENGTH];

                // http2 encodes the length of the headers in the first 3 bytes of buf, we need to update those
                u8 size_1 = 0;
                u8 size_2 = 0;
                u8 size_3 = 0;

                bpf_probe_read(&size_1, sizeof(size_1), (void *)(buf_arr + off));
                bpf_probe_read(&size_2, sizeof(size_2), (void *)(buf_arr + off + 1));
                bpf_probe_read(&size_3, sizeof(size_3), (void *)(buf_arr + off + 2));

                bpf_dbg_printk("size 1:%x, 2:%x, 3:%x", size_1, size_2, size_3);

                u32 original_size = ((u32)(size_1) << 16) | ((u32)(size_2) << 8) | size_3;

                if (original_size > 0) {
                    u8 type_byte = 0;
                    u8 key_len =
                        TP_ENCODED_LEN | 0x80; // high tagged to signify hpack encoded value
                    u8 val_len = TP_MAX_VAL_LENGTH;

                    // We don't hpack encode the value of the traceparent field, because that will require that
                    // we use bpf_loop, which in turn increases the kernel requirement to 5.17+.
                    make_tp_string(tp_str, &f_info->tp);
                    //bpf_dbg_printk("Will write %s, type = %d, key_len = %d, val_len = %d", tp_str, type_byte, key_len, val_len);

                    bpf_probe_write_user(buf_arr + (n & 0x0ffff), &type_byte, sizeof(type_byte));
                    n++;
                    // Write the length of the key = 8
                    bpf_probe_write_user(buf_arr + (n & 0x0ffff), &key_len, sizeof(key_len));
                    n++;
                    // Write 'traceparent' encoded as hpack
                    bpf_probe_write_user(buf_arr + (n & 0x0ffff), tp_encoded, sizeof(tp_encoded));
                    ;
                    n += TP_ENCODED_LEN;
                    // Write the length of the hpack encoded traceparent field
                    bpf_probe_write_user(buf_arr + (n & 0x0ffff), &val_len, sizeof(val_len));
                    n++;
                    bpf_probe_write_user(buf_arr + (n & 0x0ffff), tp_str, sizeof(tp_str));
                    n += TP_MAX_VAL_LENGTH;
                    // Update the value of n in w to reflect the new size
                    bpf_probe_write_user(
                        (void *)(w_ptr +
                                 go_offset_of(
                                     ot, (go_offset){.v = _grpc_transport_buf_writer_offset_pos})),
                        &n,
                        sizeof(n));

                    u32 new_size = original_size + HTTP2_ENCODED_HEADER_LEN;

                    bpf_dbg_printk("Changing size from %d to %d", original_size, new_size);
                    size_1 = (u8)(new_size >> 16);
                    size_2 = (u8)(new_size >> 8);
                    size_3 = (u8)(new_size);

                    bpf_probe_write_user((void *)(buf_arr + off), &size_1, sizeof(size_1));
                    bpf_probe_write_user((void *)(buf_arr + off + 1), &size_2, sizeof(size_2));
                    bpf_probe_write_user((void *)(buf_arr + off + 2), &size_3, sizeof(size_3));
                }
            }
        }
    }

    bpf_map_delete_elem(&grpc_framer_invocation_map, &g_key);
    return 0;
}
#else
SEC("uprobe/grpcFramerWriteHeaders_returns")
int beyla_uprobe_grpcFramerWriteHeaders_returns(struct pt_regs *ctx) {
    return 0;
}
#endif
