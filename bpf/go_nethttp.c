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

char __license[] SEC("license") = "Dual MIT/GPL";

#define PATH_MAX_LEN 100
#define METHOD_MAX_LEN 6 // Longer method: DELETE
#define REMOTE_ADDR_MAX_LEN 50 // We need 48: 39(ip v6 max) + 1(: separator) + 7(port length max value 65535) + 1(null terminator)
#define HOST_LEN 256 // max value of 65535 

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

// Trace of an HTTP call invocation. It is instantiated by the return uprobe and forwarded to the
// user space through the events ringbuffer.
typedef struct http_request_trace_t {
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8 method[METHOD_MAX_LEN];
    u8 path[PATH_MAX_LEN];
    u16 status;
    u8 remote_addr[REMOTE_ADDR_MAX_LEN];
    u8 host[HOST_LEN];
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
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// To be Injected from the user space during the eBPF program load & initialization
volatile const u64 url_ptr_pos;
volatile const u64 path_ptr_pos;
volatile const u64 method_ptr_pos;
volatile const u64 status_ptr_pos;
volatile const u64 remoteaddr_ptr_pos;
volatile const u64 host_ptr_pos;

// This instrumentation attaches uprobe to the following function:
// func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request)
// or other functions sharing the same signature (e.g http.Handler.ServeHTTP)
SEC("uprobe/ServeHTTP")
int uprobe_ServeHTTP(struct pt_regs *ctx) {

    // TODO: store registers in a map so we can fetch them in the return probe
    bpf_printk("=== uprobe/ServeHTTP === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_printk("goroutine_addr %lx", goroutine_addr);

    http_method_invocation invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .regs = *ctx,
    };

    // Write event
    if (bpf_map_update_elem(&ongoing_http_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_printk("can't update map element");
    }

    return 0;
}

SEC("uprobe/ServeHTTP_return")
int uprobe_ServeHttp_return(struct pt_regs *ctx) {
    bpf_printk("=== uprobe/ServeHTTP_return === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_printk("goroutine_addr %lx", goroutine_addr);

    http_method_invocation *invocation =
        bpf_map_lookup_elem(&ongoing_http_requests, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_http_requests, &goroutine_addr);
    if (invocation == NULL) {
        bpf_printk("can't read http invocation metadata");
        return 0;
    }

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_printk("can't reserve space in the ringbuffer");
        return 0;
    }
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();

    // Read arguments from the original set of registers

    // Get request struct
    void *req_ptr = GO_PARAM4(&(invocation->regs));

    // Get method from Request.Method
    if (!read_go_str("method", req_ptr, method_ptr_pos, &trace->method, sizeof(trace->method))) {
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get the remote peer information from Request.RemoteAddr
    if (!read_go_str("remote_addr", req_ptr, remoteaddr_ptr_pos, &trace->remote_addr, sizeof(trace->remote_addr))) {
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get the host information the remote supplied
    if (!read_go_str("host", req_ptr, host_ptr_pos, &trace->host, sizeof(trace->host))) {
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get path from Request.URL
    void *url_ptr = 0;
    bpf_probe_read(&url_ptr, sizeof(url_ptr), (void *)(req_ptr + url_ptr_pos));

    if (!read_go_str("path", url_ptr, path_ptr_pos, &trace->path, sizeof(trace->path))) {
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // get return code from http.ResponseWriter (interface)
    // assuming implementation of http.ResponseWriter is http.response
    // TODO: this is really a nonportable assumption
    void *resp_ptr = GO_PARAM3(&(invocation->regs));

    bpf_probe_read(&trace->status, sizeof(trace->status), (void *)(resp_ptr + status_ptr_pos));

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, 0);

    return 0;
}
