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

char __license[] SEC("license") = "Dual MIT/GPL";

#define PATH_MAX_LEN 100
#define METHOD_MAX_LEN 6 // Longer method: DELETE

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
    struct pt_regs
        regs; // we store registers on invocation to be able to fetch the arguments at return
} http_method_invocation;

// Trace of an HTTP call invocation. It is instantiated by the return uprobe and forwarded to the
// user space through the events ringbuffer.
typedef struct http_request_trace_t {
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8 method[METHOD_MAX_LEN];
    u8 path[PATH_MAX_LEN];
    u16 status;
    // TODO: remote address:port
    // TODO: dst address:port
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

    // Get method from request
    void *method_ptr = 0;
    if (bpf_probe_read(&method_ptr, sizeof(method_ptr), (void *)(req_ptr + method_ptr_pos)) != 0) {
        bpf_printk("can't read method_ptr");
    }
    u64 method_len = 0;
    if (bpf_probe_read(&method_len, sizeof(method_len), (void *)(req_ptr + (method_ptr_pos + 8))) !=
        0) {
        bpf_printk("can't read method_len");
    }
    u64 method_size = sizeof(&trace->method);

    method_size = method_size < method_len ? method_size : method_len;

    if (bpf_probe_read(trace->method, method_size, method_ptr)) {
        bpf_printk("can't read method string");
    };

    // get path from Request.URL
    void *url_ptr = 0;
    bpf_probe_read(&url_ptr, sizeof(url_ptr), (void *)(req_ptr + url_ptr_pos));
    void *path_ptr = 0;
    bpf_probe_read(&path_ptr, sizeof(path_ptr), (void *)(url_ptr + path_ptr_pos));
    u64 path_len = 0;
    bpf_probe_read(&path_len, sizeof(path_len), (void *)(url_ptr + (path_ptr_pos + 8)));
    u64 path_size = sizeof(trace->path);
    path_size = path_size < path_len ? path_size : path_len;
    bpf_probe_read(&trace->path, path_size, path_ptr);

    // get return code from http.ResponseWriter (interface)
    // assuming implementation of http.ResponseWriter is http.response
    // TODO: this is really a nonportable assumption
    void *resp_ptr = GO_PARAM3(&(invocation->regs));

    bpf_probe_read(&trace->status, sizeof(trace->status), (void *)(resp_ptr + status_ptr_pos));

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, 0);

    return 0;
}
