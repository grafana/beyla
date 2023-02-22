// Copyright The OpenTelemetry Authors
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

#include "arguments.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_SIZE 100
// TODO: make it user-configurable
#define MAX_CONCURRENT_REQUESTS 500

#define MAX_REQUEST_KEY 

typedef struct http_request_trace_t
{
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8 method[MAX_SIZE];
    u8 path[MAX_SIZE];
    // TODO: http status code
    // TODO: remote address:port
    // TODO: dst address:port
} __attribute__((packed)) http_request_trace;
// Force emitting struct sock_info into the ELF for automatic creation of Golang struct
const http_request_trace *unused __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *);  // key: pointer to the request goroutine
    __type(value, http_request_trace);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// To be Injected in init
// TODO: infer this from debugging info: https://github.com/grafana/http-autoinstrument/issues/1
volatile const u64 url_ptr_pos;
volatile const u64 path_ptr_pos;
volatile const u64 ctx_ptr_pos;
volatile const u64 method_ptr_pos;


// Current goroutine is r14, according to
// https://go.googlesource.com/go/+/refs/heads/dev.regabi/src/cmd/compile/internal-abi.md#amd64-architecture
inline void* get_goroutine_address(struct pt_regs *ctx) {
    return (void*)(ctx->r14);
}

// This instrumentation attaches uprobe to the following function:
// func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request)
// or other functions sharing the same signature (e.g http.Handler.ServeHTTP)
SEC("uprobe/ServeHTTP")
int uprobe_ServeHTTP(struct pt_regs *ctx)
{

    // TODO: store registers in a map so we can fetch them in the return probe

    bpf_printk("servemux entry\n");    
    u64 request_pos = 4;
    http_request_trace httpReq = {};
    httpReq.start_monotime_ns = bpf_ktime_get_ns();

    void *goroutine_addr = get_goroutine_address(ctx);
    bpf_printk("INPUT goroutine_addr %x", goroutine_addr);
    
    // Get request struct
    bpf_printk("rdi val %x", ctx->rdi);
    void *req_ptr = get_argument_by_reg(ctx, request_pos);    

    // Get method from request
    void *method_ptr = 0;
    if (bpf_probe_read(&method_ptr, sizeof(method_ptr), (void *)(req_ptr + method_ptr_pos)) != 0) {
        bpf_printk("can't read method_ptr");
    }
    u64 method_len = 0;
    if (bpf_probe_read(&method_len, sizeof(method_len), (void *)(req_ptr + (method_ptr_pos + 8))) != 0) {
        bpf_printk("can't read method_len");
    }
    u64 method_size = sizeof(httpReq.method);
    bpf_printk("method ptr %u", method_ptr);
    bpf_printk("method size %u", method_size);
    bpf_printk("method len %u", method_len);
    method_size = method_size < method_len ? method_size : method_len;
    bpf_printk("final method size %u", method_size);
    
    if (bpf_probe_read(httpReq.method, method_size, method_ptr)) {
        bpf_printk("can't read method string");
    };


    // get path from Request.URL
    void *url_ptr = 0;
    bpf_probe_read(&url_ptr, sizeof(url_ptr), (void *)(req_ptr + url_ptr_pos));
    void *path_ptr = 0;
    bpf_probe_read(&path_ptr, sizeof(path_ptr), (void *)(url_ptr + path_ptr_pos));
    u64 path_len = 0;
    bpf_probe_read(&path_len, sizeof(path_len), (void *)(url_ptr + (path_ptr_pos + 8)));
    u64 path_size = sizeof(httpReq.path);
    path_size = path_size < path_len ? path_size : path_len;
    bpf_probe_read(&httpReq.path, path_size, path_ptr);

    bpf_probe_read(&goroutine_addr, sizeof(goroutine_addr), (void *)(req_ptr + ctx_ptr_pos + 8));
    
    httpReq.path[0] = 'A';

    // Write event
    if (bpf_map_update_elem(&ongoing_http_requests, &goroutine_addr, &httpReq, BPF_ANY)) {
        bpf_printk("can't update map element");
    }
    bpf_printk("--------------------------");
    return 0;
}

SEC("uprobe/ServeHTTP")
int uprobe_ServeHttp_return(struct pt_regs *ctx)
{
    bpf_printk("servemux EXIT\n");
    bpf_printk("rdi val %x", ctx->rdi);

    void *goroutine_addr = get_goroutine_address(ctx);
    bpf_printk("OUTPUT goroutine_addr %x", goroutine_addr);
    // TODO: handle returned HTTP status code

    // TODO: I think we can directly delete here (check bpf_map_delete_elem documentation)
    void *httpReq_ptr = bpf_map_lookup_elem(&ongoing_http_requests, &goroutine_addr);
    if (httpReq_ptr <= 0) {
        bpf_printk("can't read http request pointer %d", httpReq_ptr);
        return 0;
    }

    http_request_trace *httpReq = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    bpf_map_delete_elem(&ongoing_http_requests, &goroutine_addr);
    if (!httpReq) {
        bpf_printk("can't reserve space in the ringbuffer");
        return 0;
    }
    // copies the hashmap info into the ringbuffer space
    bpf_probe_read((void*)httpReq, sizeof(http_request_trace), httpReq_ptr);

    httpReq->end_monotime_ns = bpf_ktime_get_ns();
    bpf_ringbuf_submit(httpReq, 0);
    
    return 0;
}

