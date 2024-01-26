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

#include "pid.h"
#include "utils.h"
#include "go_str.h"
#include "go_byte_arr.h"
#include "bpf_dbg.h"
#include "go_common.h"
#include "go_nethttp.h"
#include "go_traceparent.h"
#include "tracing.h"
#include "hpack.h"

typedef struct http_func_invocation {
    u64 start_monotime_ns;
    u64 req_ptr;
    tp_info_t tp;
} http_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, http_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_client_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, http_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_server_requests SEC(".maps");

/* HTTP Server */

// This instrumentation attaches uprobe to the following function:
// func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request)
// or other functions sharing the same signature (e.g http.Handler.ServeHTTP)
SEC("uprobe/ServeHTTP")
int uprobe_ServeHTTP(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/ServeHTTP === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *req = GO_PARAM4(ctx);

    http_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .req_ptr = (u64)req,
        .tp = {0}
    };

    if (req) {
        server_trace_parent(goroutine_addr, &invocation.tp, (void*)(req + req_header_ptr_pos));
        // TODO: if context propagation is supported, overwrite the header value in the map with the 
        // new span context and the same thread id.
    }
    
    // Write event
    if (bpf_map_update_elem(&ongoing_http_server_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }

    return 0;
}

SEC("uprobe/readRequest")
int uprobe_readRequestReturns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc readRequest returns === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    // This code is here for keepalive support on HTTP requests. Since the connection is not
    // established everytime, we set the initial goroutine start on the new read initiation.
    goroutine_metadata *g_metadata = bpf_map_lookup_elem(&ongoing_goroutines, &goroutine_addr);
    if (!g_metadata) {
        goroutine_metadata metadata = {
            .timestamp = bpf_ktime_get_ns(),
            .parent = (u64)goroutine_addr,
        };

        if (bpf_map_update_elem(&ongoing_goroutines, &goroutine_addr, &metadata, BPF_ANY)) {
            bpf_dbg_printk("can't update active goroutine");
        }
    }

    return 0;
}

static __always_inline int writeHeaderHelper(struct pt_regs *ctx, u64 req_offset) {
        bpf_dbg_printk("=== uprobe/WriteHeader === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_server_requests, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_http_server_requests, &goroutine_addr);
    if (invocation == NULL) {
        void *parent_go = (void *)find_parent_goroutine(goroutine_addr);
        if (parent_go) {
            bpf_dbg_printk("found parent goroutine for header [%llx]", parent_go);
            invocation = bpf_map_lookup_elem(&ongoing_http_server_requests, &parent_go);
            bpf_map_delete_elem(&ongoing_http_server_requests, &parent_go);
            goroutine_addr = parent_go;
        }
        if (!invocation) {
            bpf_dbg_printk("can't read http invocation metadata");
            return 0;
        }
    }

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        return 0;
    }
    
    task_pid(&trace->pid);
    trace->type = EVENT_HTTP_REQUEST;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();

    goroutine_metadata *g_metadata = bpf_map_lookup_elem(&ongoing_goroutines, &goroutine_addr);
    if (g_metadata) {
        trace->go_start_monotime_ns = g_metadata->timestamp;
        bpf_map_delete_elem(&ongoing_goroutines, &goroutine_addr);
    } else {
        trace->go_start_monotime_ns = invocation->start_monotime_ns;
    }

    // Read the response argument
    void *resp_ptr = GO_PARAM1(ctx);

    // Get request struct
    void *req_ptr = 0;
    bpf_probe_read(&req_ptr, sizeof(req_ptr), (void *)(resp_ptr + req_offset));

    if (!req_ptr) {
        bpf_printk("can't find req inside the response value");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get method from Request.Method
    if (!read_go_str("method", req_ptr, method_ptr_pos, &trace->method, sizeof(trace->method))) {
        bpf_printk("can't read http Request.Method");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get the remote peer information from Request.RemoteAddr
    if (!read_go_str("remote_addr", req_ptr, remoteaddr_ptr_pos, &trace->remote_addr, sizeof(trace->remote_addr))) {
        bpf_printk("can't read http Request.RemoteAddr");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get the host information the remote supplied
    if (!read_go_str("host", req_ptr, host_ptr_pos, &trace->host, sizeof(trace->host))) {
        bpf_printk("can't read http Request.Host");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get path from Request.URL
    void *url_ptr = 0;
    bpf_probe_read(&url_ptr, sizeof(url_ptr), (void *)(req_ptr + url_ptr_pos));

    if (!url_ptr || !read_go_str("path", url_ptr, path_ptr_pos, &trace->path, sizeof(trace->path))) {
        bpf_printk("can't read http Request.URL.Path");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    bpf_probe_read(&trace->content_length, sizeof(trace->content_length), (void *)(req_ptr + content_length_ptr_pos));

    trace->tp = invocation->tp;

    trace->status = (u16)(((u64)GO_PARAM2(ctx)) & 0x0ffff);

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

    return 0;
}

SEC("uprobe/WriteHeader")
int uprobe_WriteHeader(struct pt_regs *ctx) {
    return writeHeaderHelper(ctx, resp_req_pos);
}

#ifndef NO_HEADER_PROPAGATION
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request header map
    __type(value, u64); // the goroutine of the transport request
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} header_req_map SEC(".maps");

#endif

/* HTTP Client. We expect to see HTTP client in both HTTP server and gRPC server calls.*/
static __always_inline void roundTripStartHelper(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http roundTrip === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *req = GO_PARAM2(ctx);

    http_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .req_ptr = (u64)req,
        .tp = {0}
    };

    __attribute__((__unused__)) u8 existing_tp = client_trace_parent(goroutine_addr, &invocation.tp, (void*)(req + req_header_ptr_pos));

    // Write event
    if (bpf_map_update_elem(&ongoing_http_client_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update http client map element");
    }

#ifndef NO_HEADER_PROPAGATION
    if (!existing_tp) {
        void *headers_ptr = 0;
        bpf_probe_read(&headers_ptr, sizeof(headers_ptr), (void*)(req + req_header_ptr_pos));
        bpf_dbg_printk("goroutine_addr %lx, req ptr %llx, headers_ptr %llx", goroutine_addr, req, headers_ptr);
        
        if (headers_ptr) {
            bpf_map_update_elem(&header_req_map, &headers_ptr, &goroutine_addr, BPF_ANY);
        }
    }
#endif
}

SEC("uprobe/roundTrip")
int uprobe_roundTrip(struct pt_regs *ctx) {
    roundTripStartHelper(ctx);
    return 0;
}

SEC("uprobe/roundTrip_return")
int uprobe_roundTripReturn(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http roundTrip return === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    http_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_http_client_requests, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_http_client_requests, &goroutine_addr);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read http invocation metadata");
        return 0;
    }

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        return 0;
    }

    task_pid(&trace->pid);
    trace->type = EVENT_HTTP_CLIENT;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->go_start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();

    // Read arguments from the original set of registers

    // Get request/response struct
    void *req_ptr = (void *)invocation->req_ptr;
    void *resp_ptr = (void *)GO_PARAM1(ctx);

    // Get method from Request.Method
    if (!read_go_str("method", req_ptr, method_ptr_pos, &trace->method, sizeof(trace->method))) {
        bpf_printk("can't read http Request.Method");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get the host information of the remote
    if (!read_go_str("host", req_ptr, host_ptr_pos, &trace->host, sizeof(trace->host))) {
        bpf_printk("can't read http Request.Host");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get path from Request.URL
    void *url_ptr = 0;
    bpf_probe_read(&url_ptr, sizeof(url_ptr), (void *)(req_ptr + url_ptr_pos));

    if (!url_ptr || !read_go_str("path", url_ptr, path_ptr_pos, &trace->path, sizeof(trace->path))) {
        bpf_printk("can't read http Request.URL.Path");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    trace->tp = invocation->tp;

    bpf_probe_read(&trace->content_length, sizeof(trace->content_length), (void *)(req_ptr + content_length_ptr_pos));

    bpf_probe_read(&trace->status, sizeof(trace->status), (void *)(resp_ptr + status_code_ptr_pos));

    bpf_dbg_printk("status %d, offset %d, resp_ptr %lx", trace->status, status_code_ptr_pos, (u64)resp_ptr);

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

    return 0;
}

#ifndef NO_HEADER_PROPAGATION
// Context propagation through HTTP headers
SEC("uprobe/header_writeSubset")
int uprobe_writeSubset(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc header writeSubset === ");

    void *header_addr = GO_PARAM1(ctx);
    void *io_writer_addr = GO_PARAM3(ctx);

    bpf_dbg_printk("goroutine_addr %lx, header ptr %llx", GOROUTINE_PTR(ctx), header_addr);

    u64 *request_goaddr = bpf_map_lookup_elem(&header_req_map, &header_addr);

    if (!request_goaddr) {
        bpf_dbg_printk("Can't find parent go routine for header %llx", header_addr);
        return 0;
    }

    u64 parent_goaddr = *request_goaddr;

    http_func_invocation_t *func_inv = bpf_map_lookup_elem(&ongoing_http_client_requests, &parent_goaddr);
    if (!func_inv) {
        bpf_dbg_printk("Can't find client request for goroutine %llx", parent_goaddr);
        return 0;
    }

    unsigned char buf[TRACEPARENT_LEN];

    make_tp_string(buf, &func_inv->tp);

    void *buf_ptr = 0;
    bpf_probe_read(&buf_ptr, sizeof(buf_ptr), (void *)(io_writer_addr + io_writer_buf_ptr_pos));
    if (!buf_ptr) {
        return 0;
    }
    
    s64 size = 0;
    bpf_probe_read(&size, sizeof(s64), (void *)(io_writer_addr + io_writer_buf_ptr_pos + 8)); // grab size

    s64 len = 0;
    bpf_probe_read(&len, sizeof(s64), (void *)(io_writer_addr + io_writer_n_pos)); // grab len

    bpf_dbg_printk("buf_ptr %llx, len=%d, size=%d", (void*)buf_ptr, len, size);

    if (len < (size - TP_MAX_VAL_LENGTH - TP_MAX_KEY_LENGTH - 4)) { // 4 = strlen(":_") + strlen("\r\n")
        char key[TP_MAX_KEY_LENGTH + 2] = "Traceparent: ";
        char end[2] = "\r\n";
        bpf_probe_write_user(buf_ptr + (len & 0x0ffff), key, sizeof(key));
        len += TP_MAX_KEY_LENGTH + 2;
        bpf_probe_write_user(buf_ptr + (len & 0x0ffff), buf, sizeof(buf));
        len += TP_MAX_VAL_LENGTH;
        bpf_probe_write_user(buf_ptr + (len & 0x0ffff), end, sizeof(end));
        len += 2;
        bpf_probe_write_user((void *)(io_writer_addr + io_writer_n_pos), &len, sizeof(len));
    }

    return 0;
}
#else
SEC("uprobe/header_writeSubset")
int uprobe_writeSubset(struct pt_regs *ctx) {
    return 0;
}
#endif

// HTTP 2.0 server support
SEC("uprobe/http2ResponseWriterStateWriteHeader")
int uprobe_http2ResponseWriterStateWriteHeader(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http2 responseWriterState writeHeader === ");

    return writeHeaderHelper(ctx, rws_req_pos);
}

// HTTP 2.0 client support
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32); // key: stream id
    __type(value, u64); // the goroutine of the round trip request, which is the key for our traceparent info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} http2_req_map SEC(".maps");

SEC("uprobe/http2RoundTrip")
int uprobe_http2RoundTrip(struct pt_regs *ctx) {
    // we use the usual start helper, just like for normal http calls, but we later save
    // more context, like the streamID
    roundTripStartHelper(ctx);

    void *cc_ptr = GO_PARAM1(ctx);

    if (cc_ptr) {
        u32 stream_id = 0;
        bpf_probe_read(&stream_id, sizeof(stream_id), (void *)(cc_ptr + cc_next_stream_id_pos));
        
        bpf_dbg_printk("cc_ptr = %llx, nextStreamID=%d", cc_ptr, stream_id);
        if (stream_id) {
            void *goroutine_addr = GOROUTINE_PTR(ctx);

            bpf_map_update_elem(&http2_req_map, &stream_id, &goroutine_addr, BPF_ANY);
        }
    }

    return 0;
}

typedef struct framer_func_invocation {
    u64 framer_ptr;
    tp_info_t tp;
} framer_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void*); // key: go routine doing framer write headers
    __type(value, framer_func_invocation_t); // the goroutine of the round trip request, which is the key for our traceparent info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} framer_invocation_map SEC(".maps");

SEC("uprobe/http2FramerWriteHeaders")
int uprobe_http2FramerWriteHeaders(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http2 Framer writeHeaders === ");

    void *framer = GO_PARAM1(ctx);
    u64 stream_id = (u64)GO_PARAM2(ctx);

    bpf_printk("framer=%llx, stream_id=%lld", framer, ((u64)stream_id));

    u32 stream_lookup = (u32)stream_id;

    void **go_ptr = bpf_map_lookup_elem(&http2_req_map, &stream_lookup);
    bpf_map_delete_elem(&http2_req_map, &stream_lookup);

    if (go_ptr) {
        void *go_addr = *go_ptr;
        bpf_printk("Found existing stream data goaddr = %llx", go_addr);

        http_func_invocation_t *info = bpf_map_lookup_elem(&ongoing_http_client_requests, &go_addr);

        if (info) {
            bpf_printk("Found func info %llx", info);
            void *goroutine_addr = GOROUTINE_PTR(ctx);

            framer_func_invocation_t f_info = {
                .tp = info->tp,
                .framer_ptr = (u64)framer,
            };

            bpf_map_update_elem(&framer_invocation_map, &goroutine_addr, &f_info, BPF_ANY);
        }
    }

    return 0;
}

#define HTTP2_ENCODED_HEADER_LEN 66 // 1 + 1 + 8 + 1 + 55 = type byte + hpack_len_as_byte("traceparent") + strlen(hpack("traceparent")) + len_as_byte(55) + hpack(generated tracepanent id)

SEC("uprobe/http2FramerWriteHeaders_returns")
int uprobe_http2FramerWriteHeaders_returns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http2 Framer writeHeaders returns === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);

    framer_func_invocation_t *f_info = bpf_map_lookup_elem(&framer_invocation_map, &goroutine_addr);
    bpf_map_delete_elem(&framer_invocation_map, &goroutine_addr);

    if (f_info) {
        void *w_ptr = 0;
        bpf_probe_read(&w_ptr, sizeof(w_ptr), (void *)(f_info->framer_ptr + framer_w_pos + 8));

        if (w_ptr) {
            void *buf_arr = 0;
            s64 n = 0;
            s64 cap = 0;

            bpf_probe_read(&buf_arr, sizeof(buf_arr), (void *)(w_ptr + 16));
            bpf_probe_read(&n, sizeof(n), (void *)(w_ptr + 40));
            bpf_probe_read(&cap, sizeof(cap), (void *)(w_ptr + 24));

            bpf_dbg_printk("Found f_info, this is the place to write to w = %llx, buf=%llx, n=%d, size=%d", w_ptr, buf_arr, n, cap);
            if (buf_arr && n < (cap - HTTP2_ENCODED_HEADER_LEN)) {
                uint8_t tp_str[TP_MAX_VAL_LENGTH];

                u8 type_byte = 0;
                u8 key_len = TP_ENCODED_LEN | 0x80; // high tagged to signify hpack encoded value
                u8 val_len = TP_MAX_VAL_LENGTH;

                make_tp_string(tp_str, &f_info->tp);
                bpf_dbg_printk("Will write %s, type = %d, key_len = %d, val_len = %d", tp_str, type_byte, key_len, val_len);

                bpf_probe_write_user(buf_arr + (n & 0x0ffff), &type_byte, sizeof(type_byte));                        
                n++;
                // Write the length of the key = 8
                bpf_probe_write_user(buf_arr + (n & 0x0ffff), &key_len, sizeof(key_len));
                n++;
                // Write 'traceparent' encoded as hpack
                bpf_probe_write_user(buf_arr + (n & 0x0ffff), tp_encoded, sizeof(tp_encoded));;
                n += TP_ENCODED_LEN;
                // Write the length of the hpack encoded traceparent field 
                bpf_probe_write_user(buf_arr + (n & 0x0ffff), &val_len, sizeof(val_len));
                n++;
                bpf_probe_write_user(buf_arr + (n & 0x0ffff), tp_str, sizeof(tp_str));
                n += TP_MAX_VAL_LENGTH;
                // Update the value of n in w to reflect the new size
                bpf_probe_write_user((void *)(w_ptr + 40), &n, sizeof(n));

                // http2 encodes the length of the headers in the first 3 bytes of buf, we need to update those
                s8 size_1 = 0;
                s8 size_2 = 0;
                s8 size_3 = 0;

                bpf_probe_read(&size_1, sizeof(size_1), (void *)(buf_arr));
                bpf_probe_read(&size_2, sizeof(size_2), (void *)(buf_arr + 1));
                bpf_probe_read(&size_3, sizeof(size_3), (void *)(buf_arr + 2));

                s32 original_size = ((s32)(size_1) << 16) | ((s32)(size_2) << 8) | size_3;
                s32 new_size = original_size + HTTP2_ENCODED_HEADER_LEN;

                bpf_dbg_printk("Changing size from %d to %d", original_size, new_size);
                size_1 = (s8)(new_size >> 16);
                size_2 = (s8)(new_size >> 8);
                size_3 = (s8)(new_size);

                bpf_probe_write_user((void *)(buf_arr), &size_1, sizeof(size_1));
                bpf_probe_write_user((void *)(buf_arr+1), &size_2, sizeof(size_2));
                bpf_probe_write_user((void *)(buf_arr+2), &size_3, sizeof(size_3));
            }
        }
    }

    return 0;
}
