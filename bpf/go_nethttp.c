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

// 
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *);
    __type(value, http_request_trace);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_requests SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// To be Injected in init
// TODO: infer this from debugging info: https://github.com/grafana/http-autoinstrument/issues/1
volatile const u64 url_ptr_pos;
volatile const u64 path_ptr_pos;
volatile const u64 ctx_ptr_pos;
volatile const u64 method_ptr_pos;

// This instrumentation attaches uprobe to the following function:
// func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request)
// or other functions sharing the same signature (e.g http.Handler.ServeHTTP)
SEC("uprobe/ServeHTTP")
int uprobe_ServeHTTP(struct pt_regs *ctx)
{
    bpf_printk("servemux entry\n");
    u64 request_pos = 4;
    http_request_trace httpReq = {};
    httpReq.start_monotime_ns = bpf_ktime_get_ns();

    // Get request struct
    void *req_ptr = get_argument(ctx, request_pos);

    // Get method from request
    void *method_ptr = 0;
    bpf_probe_read(&method_ptr, sizeof(method_ptr), (void *)(req_ptr + method_ptr_pos));
    u64 method_len = 0;
    bpf_probe_read(&method_len, sizeof(method_len), (void *)(req_ptr + (method_ptr_pos + 8)));
    u64 method_size = sizeof(httpReq.method);
    method_size = method_size < method_len ? method_size : method_len;
    bpf_probe_read(&httpReq.method, method_size, method_ptr);

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

    // Get Request.ctx
    void *ctx_iface = 0;
    bpf_probe_read(&ctx_iface, sizeof(ctx_iface), (void *)(req_ptr + ctx_ptr_pos + 8));

    // Write event
    bpf_map_update_elem(&ongoing_http_requests, &ctx_iface, &httpReq, 0);
    return 0;
}

SEC("uprobe/ServeHTTP_return")
int uprobe_ServeHttp_return(struct pt_regs *ctx)
{
    bpf_printk("servemux EXIT\n");
    u64 request_pos = 4;
    void *req_ptr = get_argument(ctx, request_pos);
    void *ctx_iface = 0;
    bpf_probe_read(&ctx_iface, sizeof(ctx_iface), (void *)(req_ptr + ctx_ptr_pos + 8));
    // TODO: handle returned HTTP status code

    // TODO: I think we can directly delete here (check bpf_map_delete_elem documentation)
    void *httpReq_ptr = bpf_map_lookup_elem(&ongoing_http_requests, &ctx_iface);
    http_request_trace httpReq = {};
    bpf_probe_read(&httpReq, sizeof(httpReq), httpReq_ptr);
    httpReq.end_monotime_ns = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &httpReq, sizeof(httpReq));

    bpf_map_delete_elem(&ongoing_http_requests, &ctx_iface);
    return 0;
}