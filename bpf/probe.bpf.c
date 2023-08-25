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
#include "span_context.h"
#include "go_context.h"
#include "go_types.h"
#include "uprobe.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define PATH_MAX_LEN 100
#define MAX_BUCKETS 8
#define METHOD_MAX_LEN 7
#define MAX_CONCURRENT 50
#define W3C_KEY_LENGTH 11
#define W3C_VAL_LENGTH 55

struct http_request_t
{
    BASE_SPAN_PROPERTIES
    char method[METHOD_MAX_LEN];
    char path[PATH_MAX_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *);
    __type(value, struct http_request_t);
    __uint(max_entries, MAX_CONCURRENT);
} http_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct map_bucket));
    __uint(max_entries, 1);
} golang_mapbucket_storage_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct span_context));
    __uint(max_entries, 1);
} parent_span_context_storage_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Injected in init
volatile const u64 method_ptr_pos;
volatile const u64 url_ptr_pos;
volatile const u64 path_ptr_pos;
volatile const u64 ctx_ptr_pos;
volatile const u64 headers_ptr_pos;

static __always_inline struct span_context *extract_context_from_req_headers(void *headers_ptr_ptr)
{
    void *headers_ptr;
    long res;
    res = bpf_probe_read(&headers_ptr, sizeof(headers_ptr), headers_ptr_ptr);
    if (res < 0)
    {
        return NULL;
    }
    u64 headers_count = 0;
    res = bpf_probe_read(&headers_count, sizeof(headers_count), headers_ptr);
    if (res < 0)
    {
        return NULL;
    }
    if (headers_count == 0)
    {
        return NULL;
    }
    unsigned char log_2_bucket_count;
    res = bpf_probe_read(&log_2_bucket_count, sizeof(log_2_bucket_count), headers_ptr + 9);
    if (res < 0)
    {
        return NULL;
    }
    u64 bucket_count = 1 << log_2_bucket_count;
    void *header_buckets;
    res = bpf_probe_read(&header_buckets, sizeof(header_buckets), headers_ptr + 16);
    if (res < 0)
    {
        return NULL;
    }
    u32 map_id = 0;
    struct map_bucket *map_value = bpf_map_lookup_elem(&golang_mapbucket_storage_map, &map_id);
    if (!map_value)
    {
        return NULL;
    }

    for (u64 j = 0; j < MAX_BUCKETS; j++)
    {
        if (j >= bucket_count)
        {
            break;
        }
        res = bpf_probe_read(map_value, sizeof(struct map_bucket), header_buckets + (j * sizeof(struct map_bucket)));
        if (res < 0)
        {
            continue;
        }
        for (u64 i = 0; i < 8; i++)
        {
            if (map_value->tophash[i] == 0)
            {
                continue;
            }
            if (map_value->keys[i].len != W3C_KEY_LENGTH)
            {
                continue;
            }
            char current_header_key[W3C_KEY_LENGTH];
            bpf_probe_read(current_header_key, sizeof(current_header_key), map_value->keys[i].str);
            if (!bpf_memcmp(current_header_key, "traceparent", W3C_KEY_LENGTH) && !bpf_memcmp(current_header_key, "Traceparent", W3C_KEY_LENGTH))
            {
                continue;
            }
            void *traceparent_header_value_ptr = map_value->values[i].array;
            struct go_string traceparent_header_value_go_str;
            res = bpf_probe_read(&traceparent_header_value_go_str, sizeof(traceparent_header_value_go_str), traceparent_header_value_ptr);
            if (res < 0)
            {
                return NULL;
            }
            if (traceparent_header_value_go_str.len != W3C_VAL_LENGTH)
            {
                continue;
            }
            char traceparent_header_value[W3C_VAL_LENGTH];
            res = bpf_probe_read(&traceparent_header_value, sizeof(traceparent_header_value), traceparent_header_value_go_str.str);
            if (res < 0)
            {
                return NULL;
            }
            struct span_context *parent_span_context = bpf_map_lookup_elem(&parent_span_context_storage_map, &map_id);
            if (!parent_span_context)
            {
                return NULL;
            }
            w3c_string_to_span_context(traceparent_header_value, parent_span_context);
            return parent_span_context;
        }
    }
    return NULL;
}

// This instrumentation attaches uprobe to the following function:
// func (mux *ServeMux) ServeHTTP(w ResponseWriter, r *Request)
SEC("uprobe/ServerMux_ServeHTTP")
int uprobe_ServerMux_ServeHTTP(struct pt_regs *ctx)
{
    u64 request_pos = 4;
    struct http_request_t httpReq = {};
    httpReq.start_time = bpf_ktime_get_ns();

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

    // Propagate context
    struct span_context *parent_ctx = extract_context_from_req_headers(req_ptr + headers_ptr_pos);
    if (parent_ctx != NULL)
    {
        httpReq.psc = *parent_ctx;
        copy_byte_arrays(httpReq.psc.TraceID, httpReq.sc.TraceID, TRACE_ID_SIZE);
        generate_random_bytes(httpReq.sc.SpanID, SPAN_ID_SIZE);
    }
    else
    {
        httpReq.sc = generate_span_context();
    }

    // Get key
    void *req_ctx_ptr = 0;
    bpf_probe_read(&req_ctx_ptr, sizeof(req_ctx_ptr), (void *)(req_ptr + ctx_ptr_pos));
    void *key = get_consistent_key(ctx, (void *)(req_ptr + ctx_ptr_pos));

    // Write event
    httpReq.sc = generate_span_context();
    bpf_map_update_elem(&http_events, &key, &httpReq, 0);
    start_tracking_span(req_ctx_ptr, &httpReq.sc);
    return 0;
}

UPROBE_RETURN(ServerMux_ServeHTTP, struct http_request_t, 4, ctx_ptr_pos, http_events, events)