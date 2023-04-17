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

#include "utils.h"
#include "go_str.h"
#include "go_byte_arr.h"
#include "bpf_dbg.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define EVENT_HTTP_REQUEST 1
#define EVENT_GRPC_REQUEST 2

#define PATH_MAX_LEN 100
#define METHOD_MAX_LEN 6 // Longest method: DELETE
#define REMOTE_ADDR_MAX_LEN 50 // We need 48: 39(ip v6 max) + 1(: separator) + 7(port length max value 65535) + 1(null terminator)
#define HOST_LEN 256 // can be a fully qualified DNS name

// TODO: make it user-configurable
#define MAX_CONCURRENT_REQUESTS 500

// Temporary information about a function invocation. It stores the invocation time of a function
// as well as the value of registers at the invocation time. This way we can retrieve them at the
// return uprobes so we can know the values of the function arguments (which are passed as registers
// since Go 1.17).
// This element is created in the function start probe and stored in the ongoing_http_requests hashmaps.
// Then it is retrieved in the return uprobes and used to know the HTTP call duration as well as its
// attributes (method, path, and status code).
typedef struct http_method_invocation_t {
    u64 start_monotime_ns;
    struct pt_regs regs; // we store registers on invocation to be able to fetch the arguments at return
} http_method_invocation;

typedef struct grpc_method_data_t {
    u64 start_monotime_ns;
    u64 status;          // we only need u16, but regs below must be 8-byte aligned
    struct pt_regs regs; // we store registers on invocation to be able to fetch the arguments at return
} grpc_method_data;

// Trace of an HTTP call invocation. It is instantiated by the return uprobe and forwarded to the
// user space through the events ringbuffer.
typedef struct http_request_trace_t {
    u8  type;
    u64 go_start_monotime_ns;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8  method[METHOD_MAX_LEN];
    u8  path[PATH_MAX_LEN];
    u16 status;
    u8  remote_addr[REMOTE_ADDR_MAX_LEN];
    u64 remote_addr_len;
    u8  host[HOST_LEN];
    u64 host_len;
    u32 host_port;
    s64 content_length;
} __attribute__((packed)) http_request_trace;
// Force emitting struct sock_info into the ELF for automatic creation of Golang struct
const http_request_trace *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, http_method_invocation);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, grpc_method_data);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the goroutine
    __type(value, u64);  // value: timestamp of the goroutine creation
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_goroutines SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// To be Injected from the user space during the eBPF program load & initialization
// HTTP
volatile const u64 url_ptr_pos;
volatile const u64 path_ptr_pos;
volatile const u64 method_ptr_pos;
volatile const u64 status_ptr_pos;
volatile const u64 remoteaddr_ptr_pos;
volatile const u64 host_ptr_pos;
volatile const u64 content_length_ptr_pos;
// GRPC
volatile const u64 grpc_stream_st_ptr_pos;
volatile const u64 grpc_stream_method_ptr_pos;
volatile const u64 grpc_stream_id_ptr_pos;
volatile const u64 grpc_status_s_pos;
volatile const u64 grpc_status_code_ptr_pos;
volatile const u64 grpc_st_remoteaddr_ptr_pos;
volatile const u64 grpc_st_localaddr_ptr_pos;
volatile const u64 tcp_addr_port_ptr_pos;
volatile const u64 tcp_addr_ip_ptr_pos;

/* HTTP */

// This instrumentation attaches uprobe to the following function:
// func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request)
// or other functions sharing the same signature (e.g http.Handler.ServeHTTP)
SEC("uprobe/ServeHTTP")
int uprobe_ServeHTTP(struct pt_regs *ctx) {

    // TODO: store registers in a map so we can fetch them in the return probe
    bpf_dbg_printk("=== uprobe/ServeHTTP === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    http_method_invocation invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .regs = *ctx,
    };

    // Write event
    if (bpf_map_update_elem(&ongoing_http_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }

    return 0;
}

SEC("uprobe/ServeHTTP_return")
int uprobe_ServeHttp_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/ServeHTTP_return === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    http_method_invocation *invocation =
        bpf_map_lookup_elem(&ongoing_http_requests, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_http_requests, &goroutine_addr);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read http invocation metadata");
        return 0;
    }

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        return 0;
    }
    trace->type = EVENT_HTTP_REQUEST;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();

    u64 *go_start_monotime_ns = bpf_map_lookup_elem(&ongoing_goroutines, &goroutine_addr);
    if (go_start_monotime_ns) {
        trace->go_start_monotime_ns = *go_start_monotime_ns;
        bpf_map_delete_elem(&ongoing_goroutines, &goroutine_addr);
    } else {
        trace->go_start_monotime_ns = invocation->start_monotime_ns;
    }

    // Read arguments from the original set of registers

    // Get request struct
    void *req_ptr = GO_PARAM4(&(invocation->regs));

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

    // get return code from http.ResponseWriter (interface)
    // assuming implementation of http.ResponseWriter is http.response
    // TODO: this is really a nonportable assumption
    void *resp_ptr = GO_PARAM3(&(invocation->regs));

    bpf_probe_read(&trace->status, sizeof(trace->status), (void *)(resp_ptr + status_ptr_pos));

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, 0);

    return 0;
}

/* GRPC */

SEC("uprobe/server_handleStream")
int uprobe_server_handleStream(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/server_handleStream === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    grpc_method_data invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .regs = *ctx,
        .status = -1
    };

    if (bpf_map_update_elem(&ongoing_grpc_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update grpc map element");
    }

    return 0;
}

SEC("uprobe/server_handleStream")
int uprobe_server_handleStream_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/server_handleStream return === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    grpc_method_data *invocation =
        bpf_map_lookup_elem(&ongoing_grpc_requests, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_grpc_requests, &goroutine_addr);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read grpc invocation metadata");
        return 0;
    }

    void *stream_ptr = GO_PARAM4(&(invocation->regs));
    bpf_dbg_printk("stream_ptr %lx, method pos %lx", stream_ptr, grpc_stream_method_ptr_pos);

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        return 0;
    }
    trace->type = EVENT_GRPC_REQUEST;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->status = invocation->status;

    u64 *go_start_monotime_ns = bpf_map_lookup_elem(&ongoing_goroutines, &goroutine_addr);
    if (go_start_monotime_ns) {
        trace->go_start_monotime_ns = *go_start_monotime_ns;
        bpf_map_delete_elem(&ongoing_goroutines, &goroutine_addr);
    } else {
        trace->go_start_monotime_ns = invocation->start_monotime_ns;
    }

    // Get method from transport.Stream.Method
    if (!read_go_str("grpc method", stream_ptr, grpc_stream_method_ptr_pos, &trace->path, sizeof(trace->path))) {
        bpf_printk("can't read grpc transport.Stream.Method");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    void *st_ptr = 0;
    // Read the embedded object ptr
    bpf_probe_read(&st_ptr, sizeof(st_ptr), (void *)(stream_ptr + grpc_stream_st_ptr_pos + sizeof(void *)));

    if (st_ptr) {
        void *peer_ptr = 0; 
        bpf_probe_read(&peer_ptr, sizeof(peer_ptr), (void *)(st_ptr + grpc_st_remoteaddr_ptr_pos + sizeof(void *)));

        if (peer_ptr) {
            u64 remote_addr_len = 0;
            if (!read_go_byte_arr("grpc peer ptr", peer_ptr, tcp_addr_ip_ptr_pos, &trace->remote_addr, &remote_addr_len, sizeof(trace->remote_addr))) {
                bpf_printk("can't read grpc peer ptr");
                bpf_ringbuf_discard(trace, 0);
                return 0;
            }
            trace->remote_addr_len = remote_addr_len;
        }

        void *host_ptr = 0;
        bpf_probe_read(&host_ptr, sizeof(host_ptr), (void *)(st_ptr + grpc_st_localaddr_ptr_pos + sizeof(void *)));

        if (host_ptr) {
            u64 host_len = 0;

            if (!read_go_byte_arr("grpc host ptr", host_ptr, tcp_addr_ip_ptr_pos, &trace->host, &host_len,  sizeof(trace->host))) {
                bpf_printk("can't read grpc host ptr");
                bpf_ringbuf_discard(trace, 0);
                return 0;
            }
            trace->host_len = host_len;

            bpf_probe_read(&trace->host_port, sizeof(trace->host_port), (void *)(host_ptr + tcp_addr_port_ptr_pos));
        }
    }

    trace->end_monotime_ns = bpf_ktime_get_ns();
    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, 0);

    return 0;
}

SEC("uprobe/transport_writeStatus")
int uprobe_transport_writeStatus(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/transport_writeStatus === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    grpc_method_data *invocation =
        bpf_map_lookup_elem(&ongoing_grpc_requests, &goroutine_addr);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read grpc invocation metadata in write status");
        return 0;
    }

    void *status_ptr = GO_PARAM3(ctx);
    bpf_dbg_printk("status_ptr %lx", status_ptr);

    if (status_ptr != NULL) {
        void *s_ptr;
        bpf_probe_read(&s_ptr, sizeof(s_ptr), (void *)(status_ptr + grpc_status_s_pos));

        bpf_dbg_printk("s_ptr %lx", s_ptr);

        if (s_ptr != NULL) {
            bpf_probe_read(&invocation->status, sizeof(invocation->status), (void *)(s_ptr + grpc_status_code_ptr_pos));
            bpf_dbg_printk("status code %d", invocation->status);
            bpf_map_update_elem(&ongoing_grpc_requests, &goroutine_addr, invocation, BPF_ANY);
        }
    }

    return 0;
}

/* RUNTIME */

SEC("uprobe/runtime_newproc1")
int uprobe_proc_newproc1_ret(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc newproc1 returns === ");

    void *goroutine_addr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    u64 timestamp = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&ongoing_goroutines, &goroutine_addr, &timestamp, BPF_ANY)) {
        bpf_dbg_printk("can't update grpc map element");
    }

    return 0;
}

SEC("uprobe/runtime_goexit1")
int uprobe_proc_goexit1(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc goexit1 === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    bpf_map_delete_elem(&ongoing_goroutines, &goroutine_addr);

    return 0;
}
