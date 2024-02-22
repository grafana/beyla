// Copyright The OpenTelemetry Authors
// Copyright Grafana Labs
//
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

#include "pid_types.h"
#include "utils.h"
#include "go_str.h"
#include "go_byte_arr.h"
#include "bpf_dbg.h"
#include "go_common.h"
#include "go_nethttp.h"
#include "go_traceparent.h"
#include "http_types.h"
#include "tracing.h"
#include "hpack.h"
#include "ringbuf.h"

typedef struct http_func_invocation {
    u64 start_monotime_ns;
    tp_info_t tp;
} http_func_invocation_t;

typedef struct http_client_data {
    u8  method[METHOD_MAX_LEN];
    u8  path[PATH_MAX_LEN];
    u8  host[HOST_LEN];
    s64 content_length;

    pid_info pid;
} http_client_data_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, http_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_client_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, http_client_data_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_client_requests_data SEC(".maps");

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
    if (invocation == NULL) {
        void *parent_go = (void *)find_parent_goroutine(goroutine_addr);
        if (parent_go) {
            bpf_dbg_printk("found parent goroutine for header [%llx]", parent_go);
            invocation = bpf_map_lookup_elem(&ongoing_http_server_requests, &parent_go);
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
        goto done;
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
        goto done;
    }

    // Get method from Request.Method
    if (!read_go_str("method", req_ptr, method_ptr_pos, &trace->method, sizeof(trace->method))) {
        bpf_printk("can't read http Request.Method");
        bpf_ringbuf_discard(trace, 0);
        goto done;
    }

    // Get the remote peer information from Request.RemoteAddr
    if (!read_go_str("remote_addr", req_ptr, remoteaddr_ptr_pos, &trace->remote_addr, sizeof(trace->remote_addr))) {
        bpf_printk("can't read http Request.RemoteAddr");
        bpf_ringbuf_discard(trace, 0);
        goto done;
    }

    // Get the host information the remote supplied
    if (!read_go_str("host", req_ptr, host_ptr_pos, &trace->host, sizeof(trace->host))) {
        bpf_printk("can't read http Request.Host");
        bpf_ringbuf_discard(trace, 0);
        goto done;
    }

    // Get path from Request.URL
    void *url_ptr = 0;
    bpf_probe_read(&url_ptr, sizeof(url_ptr), (void *)(req_ptr + url_ptr_pos));

    if (!url_ptr || !read_go_str("path", url_ptr, path_ptr_pos, &trace->path, sizeof(trace->path))) {
        bpf_printk("can't read http Request.URL.Path");
        bpf_ringbuf_discard(trace, 0);
        goto done;
    }

    bpf_probe_read(&trace->content_length, sizeof(trace->content_length), (void *)(req_ptr + content_length_ptr_pos));

    trace->tp = invocation->tp;

    trace->status = (u16)(((u64)GO_PARAM2(ctx)) & 0x0ffff);

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

done:
    bpf_map_delete_elem(&ongoing_http_server_requests, &goroutine_addr);
    bpf_map_delete_elem(&go_trace_map, &goroutine_addr);
    return 0;
}

SEC("uprobe/WriteHeader")
int uprobe_WriteHeader(struct pt_regs *ctx) {
    return writeHeaderHelper(ctx, resp_req_pos);
}

#ifndef NO_HEADER_PROPAGATION
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
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
        .tp = {0}
    };

    __attribute__((__unused__)) u8 existing_tp = client_trace_parent(goroutine_addr, &invocation.tp, (void*)(req + req_header_ptr_pos));

    http_client_data_t trace = {0};

    // Get method from Request.Method
    if (!read_go_str("method", req, method_ptr_pos, &trace.method, sizeof(trace.method))) {
        bpf_printk("can't read http Request.Method");
        return;
    }

    // Get the host information of the remote
    if (!read_go_str("host", req, host_ptr_pos, &trace.host, sizeof(trace.host))) {
        bpf_printk("can't read http Request.Host");
        return;
    }

    bpf_probe_read(&trace.content_length, sizeof(trace.content_length), (void *)(req + content_length_ptr_pos));

    // Get path from Request.URL
    void *url_ptr = 0;
    bpf_probe_read(&url_ptr, sizeof(url_ptr), (void *)(req + url_ptr_pos));

    if (!url_ptr || !read_go_str("path", url_ptr, path_ptr_pos, &trace.path, sizeof(trace.path))) {
        bpf_printk("can't read http Request.URL.Path");
        return;
    }

    // Write event
    if (bpf_map_update_elem(&ongoing_http_client_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update http client map element");
    }

    bpf_map_update_elem(&ongoing_http_client_requests_data, &goroutine_addr, &trace, BPF_ANY);

#ifndef NO_HEADER_PROPAGATION
    //if (!existing_tp) {
        void *headers_ptr = 0;
        bpf_probe_read(&headers_ptr, sizeof(headers_ptr), (void*)(req + req_header_ptr_pos));
        bpf_dbg_printk("goroutine_addr %lx, req ptr %llx, headers_ptr %llx", goroutine_addr, req, headers_ptr);
        
        if (headers_ptr) {
            bpf_map_update_elem(&header_req_map, &headers_ptr, &goroutine_addr, BPF_ANY);
        }
    //}
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
    if (invocation == NULL) {
        bpf_dbg_printk("can't read http invocation metadata");
        goto done;
    }

    http_client_data_t *data = bpf_map_lookup_elem(&ongoing_http_client_requests_data, &goroutine_addr);
    if (data == NULL) {
        bpf_dbg_printk("can't read http client invocation data");
        goto done;
    }

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        goto done;
    }

    task_pid(&trace->pid);
    trace->type = EVENT_HTTP_CLIENT;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->go_start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();

    // Copy the values read on request start
    __builtin_memcpy(trace->method, data->method, sizeof(trace->method));
    __builtin_memcpy(trace->host, data->host, sizeof(trace->host));
    __builtin_memcpy(trace->path, data->path, sizeof(trace->path));
    trace->content_length = data->content_length;

    // Get request/response struct

    void *resp_ptr = (void *)GO_PARAM1(ctx);

    trace->tp = invocation->tp;

    bpf_probe_read(&trace->status, sizeof(trace->status), (void *)(resp_ptr + status_code_ptr_pos));

    bpf_dbg_printk("status %d, offset %d, resp_ptr %lx", trace->status, status_code_ptr_pos, (u64)resp_ptr);

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

done:
    bpf_map_delete_elem(&ongoing_http_client_requests, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_http_client_requests_data, &goroutine_addr);
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
        goto done;
    }

    unsigned char buf[TRACEPARENT_LEN];

    make_tp_string(buf, &func_inv->tp);

    void *buf_ptr = 0;
    bpf_probe_read(&buf_ptr, sizeof(buf_ptr), (void *)(io_writer_addr + io_writer_buf_ptr_pos));
    if (!buf_ptr) {
        goto done;
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

done:
    bpf_map_delete_elem(&header_req_map, &header_addr);
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
#ifndef NO_HEADER_PROPAGATION
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32); // key: stream id
    __type(value, u64); // the goroutine of the round trip request, which is the key for our traceparent info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} http2_req_map SEC(".maps");
#endif

SEC("uprobe/http2RoundTrip")
int uprobe_http2RoundTrip(struct pt_regs *ctx) {
    // we use the usual start helper, just like for normal http calls, but we later save
    // more context, like the streamID
    roundTripStartHelper(ctx);

#ifndef NO_HEADER_PROPAGATION
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
#endif    

    return 0;
}

#ifndef NO_HEADER_PROPAGATION
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

    if (go_ptr) {
        void *go_addr = *go_ptr;
        bpf_dbg_printk("Found existing stream data goaddr = %llx", go_addr);

        http_func_invocation_t *info = bpf_map_lookup_elem(&ongoing_http_client_requests, &go_addr);

        if (info) {
            bpf_dbg_printk("Found func info %llx", info);
            void *goroutine_addr = GOROUTINE_PTR(ctx);

            framer_func_invocation_t f_info = {
                .tp = info->tp,
                .framer_ptr = (u64)framer,
            };

            bpf_map_update_elem(&framer_invocation_map, &goroutine_addr, &f_info, BPF_ANY);
        }
    }

    bpf_map_delete_elem(&http2_req_map, &stream_lookup);
    return 0;
}
#else
SEC("uprobe/http2FramerWriteHeaders")
int uprobe_http2FramerWriteHeaders(struct pt_regs *ctx) {
    return 0;
}
#endif

#ifndef NO_HEADER_PROPAGATION
#define HTTP2_ENCODED_HEADER_LEN 66 // 1 + 1 + 8 + 1 + 55 = type byte + hpack_len_as_byte("traceparent") + strlen(hpack("traceparent")) + len_as_byte(55) + generated traceparent id

SEC("uprobe/http2FramerWriteHeaders_returns")
int uprobe_http2FramerWriteHeaders_returns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http2 Framer writeHeaders returns === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);

    framer_func_invocation_t *f_info = bpf_map_lookup_elem(&framer_invocation_map, &goroutine_addr);

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

            bpf_dbg_printk("Found f_info, this is the place to write to w = %llx, buf=%llx, n=%lld, size=%lld", w_ptr, buf_arr, n, cap);
            if (buf_arr && n < (cap - HTTP2_ENCODED_HEADER_LEN)) {
                uint8_t tp_str[TP_MAX_VAL_LENGTH];

                u8 type_byte = 0;
                u8 key_len = TP_ENCODED_LEN | 0x80; // high tagged to signify hpack encoded value
                u8 val_len = TP_MAX_VAL_LENGTH;

                // We don't hpack encode the value of the traceparent field, because that will require that 
                // we use bpf_loop, which in turn increases the kernel requirement to 5.17+.
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

    bpf_map_delete_elem(&framer_invocation_map, &goroutine_addr);
    return 0;
}
#else
SEC("uprobe/http2FramerWriteHeaders_returns")
int uprobe_http2FramerWriteHeaders_returns(struct pt_regs *ctx) {
    return 0;
}
#endif 


static __always_inline void read_ip_and_port(u8 *dst_ip, u16 *dst_port, void *src) {
    s64 addr_len = 0;
    void *addr_ip = 0;

    bpf_probe_read(dst_port, sizeof(u16), (void *)(src + tcp_addr_port_ptr_pos));
    bpf_probe_read(&addr_ip, sizeof(addr_ip), (void *)(src + tcp_addr_ip_ptr_pos));
    if (addr_ip) {
        bpf_probe_read(&addr_len, sizeof(addr_len), (void *)(src + tcp_addr_ip_ptr_pos + 8));
        if (addr_len == 4) {
            __builtin_memcpy(dst_ip, ip4ip6_prefix, sizeof(ip4ip6_prefix));
            bpf_probe_read(dst_ip + sizeof(ip4ip6_prefix), 4, addr_ip);
        } else if (addr_len == 16) {
            bpf_probe_read(dst_ip, 16, addr_ip);
        }
    }
}

// HTTP black-box context propagation
static __always_inline void get_conn_info(void *conn_ptr, connection_info_t *info) {
    if (conn_ptr) {
        void *fd_ptr = 0;
        bpf_probe_read(&fd_ptr, sizeof(fd_ptr), (void *)(conn_ptr + conn_fd_pos)); // find fd

        bpf_dbg_printk("Found fd ptr %llx", fd_ptr);

        if (fd_ptr) {
            void *laddr_ptr = 0;
            void *raddr_ptr = 0;

            bpf_probe_read(&laddr_ptr, sizeof(laddr_ptr), (void *)(fd_ptr + fd_laddr_pos + 8)); // find laddr
            bpf_probe_read(&raddr_ptr, sizeof(raddr_ptr), (void *)(fd_ptr + fd_raddr_pos + 8)); // find raddr

            if (laddr_ptr && raddr_ptr) {
                bpf_dbg_printk("laddr %llx, raddr %llx", laddr_ptr, raddr_ptr);

                // read local
                read_ip_and_port(info->s_addr, &info->s_port, laddr_ptr);

                // read remote
                read_ip_and_port(info->d_addr, &info->d_port, raddr_ptr);

                sort_connection_info(info);
                //dbg_print_http_connection_info(info);
            }
        }
    }
}

SEC("uprobe/connServe")
int uprobe_connServe(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http conn serve === ");

    void *c_ptr = GO_PARAM1(ctx);
    if (c_ptr) {
        void *rwc_ptr = c_ptr + 8 + c_rwc_pos; // embedded struct
        if (rwc_ptr) {
            void *conn_ptr = 0;
            bpf_probe_read(&conn_ptr, sizeof(conn_ptr), (void *)(rwc_ptr + rwc_conn_pos)); // find conn
            if (conn_ptr) {
                void *goroutine_addr = GOROUTINE_PTR(ctx);
                connection_info_t conn = {0};
                get_conn_info(conn_ptr, &conn);

                bpf_map_update_elem(&ongoing_http_server_connections, &goroutine_addr, &conn, BPF_ANY);
            }
        }
    }

    return 0;
}

SEC("uprobe/connServeRet")
int uprobe_connServeRet(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http conn serve ret === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    bpf_map_delete_elem(&ongoing_http_server_connections, &goroutine_addr);

    return 0;
}

SEC("uprobe/persistConnRoundTrip")
int uprobe_persistConnRoundTrip(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc http persistConn roundTrip === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    http_func_invocation_t *invocation = bpf_map_lookup_elem(&ongoing_http_client_requests, &goroutine_addr);
    if (!invocation) {
        bpf_dbg_printk("can't find invocation info for client call, this might be a bug");
        return 0;
    }

    void *pc_ptr = GO_PARAM1(ctx);
    if (pc_ptr) {
        void *conn_conn_ptr = pc_ptr + 8 + pc_conn_pos; // embedded struct
        if (conn_conn_ptr) {
            void *conn_ptr = 0;
            bpf_probe_read(&conn_ptr, sizeof(conn_ptr), (void *)(conn_conn_ptr + rwc_conn_pos)); // find conn
            if (conn_ptr) {
                connection_info_t conn = {0};
                get_conn_info(conn_ptr, &conn);
                u64 pid_tid = bpf_get_current_pid_tgid();
                u32 pid = pid_from_pid_tgid(pid_tid);
                tp_info_pid_t tp_p = {
                    .pid = pid,
                    .valid = 1,
                };

                tp_clone(&tp_p.tp, &invocation->tp);
                tp_p.tp.ts = bpf_ktime_get_ns();
                bpf_dbg_printk("storing trace_map info for black-box tracing");
                bpf_map_update_elem(&trace_map, &conn, &tp_p, BPF_ANY);
            }
        }
    }

    return 0;
}

// SQL support
// This implementation was inspired by https://github.com/open-telemetry/opentelemetry-go-instrumentation/blob/ca1afccea6ec520d18238c3865024a9f5b9c17fe/internal/pkg/instrumentors/bpf/database/sql/bpf/probe.bpf.c
// and has been modified since.

typedef struct sql_func_invocation {
    u64 start_monotime_ns;
    u64 sql_param;
    u64 query_len;
    tp_info_t tp;
} sql_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, sql_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_sql_queries SEC(".maps");

SEC("uprobe/queryDC")
int uprobe_queryDC(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/queryDC === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *sql_param = GO_PARAM8(ctx);
    void *query_len = GO_PARAM9(ctx);

    sql_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .sql_param = (u64)sql_param,
        .query_len = (u64)query_len,
        .tp = {0}
    };

    // We don't look up in the headers, no http/grpc request, therefore 0 as last argument
    client_trace_parent(goroutine_addr, &invocation.tp, 0);

    // Write event
    if (bpf_map_update_elem(&ongoing_sql_queries, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }

    return 0;
}

SEC("uprobe/queryDC")
int uprobe_queryDCReturn(struct pt_regs *ctx) {

    bpf_dbg_printk("=== uprobe/queryDC return === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    sql_func_invocation_t *invocation = bpf_map_lookup_elem(&ongoing_sql_queries, &goroutine_addr);
    if (invocation == NULL) {
        bpf_dbg_printk("Request not found for this goroutine");
        return 0;
    }
    bpf_map_delete_elem(&ongoing_sql_queries, &goroutine_addr);

    sql_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(sql_request_trace), 0);
    if (trace) {
        task_pid(&trace->pid);
        trace->type = EVENT_SQL_CLIENT;
        trace->start_monotime_ns = invocation->start_monotime_ns;
        trace->end_monotime_ns = bpf_ktime_get_ns();

        void *resp_ptr = GO_PARAM1(ctx);
        trace->status = (resp_ptr == NULL);
        trace->tp = invocation->tp;

        u64 query_len = invocation->query_len;
        if (query_len > sizeof(trace->sql)) {
            query_len = sizeof(trace->sql);
        }
        bpf_probe_read(trace->sql, query_len, (void*)invocation->sql_param);
        bpf_dbg_printk("Found sql statement %s", trace->sql);
        // submit the completed trace via ringbuffer
        bpf_ringbuf_submit(trace, get_flags());
    } else {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
    }
    return 0;
}