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
#include "http_types.h"
#include "tracing.h"

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

SEC("uprobe/roundTrip")
int uprobe_roundTrip(struct pt_regs *ctx) {
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

static __always_inline void read_ip_and_port(u8 *dst_ip, u16 *dst_port, void *src) {
    s64 addr_len = 0;
    void *addr_ip = 0;

    bpf_probe_read(&dst_port, sizeof(u16), (void *)(src + tcp_addr_port_ptr_pos));
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
                dbg_print_http_connection_info(info);
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
                u32 pid = pid_from_pid_tgid(bpf_get_current_pid_tgid());
                tp_info_pid_t tp_p = {
                    .pid = pid,
                    .valid = 1,
                    .tp = invocation->tp
                };
            
                tp_p.tp.ts = bpf_ktime_get_ns();
                bpf_dbg_printk("storing trace_map info for black-box tracing");
                bpf_map_update_elem(&trace_map, &conn, &tp_p, BPF_ANY);
            }
        }
    }

    return 0;
}
