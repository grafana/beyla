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

#include "headers/bpf_tracing.h"
#include "common.h"
#include "bpf_helpers.h"
#include "bpf_dbg.h"
#include "utils.h"
#include <stdbool.h>

#include "arguments.h"
#include "span_context.h"
#include "go_context.h"
//#include "go_types.h"
//#include "uprobe.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_QUERY_SIZE 100
#define MAX_CONCURRENT 50

#define TRACE_ID_SIZE 16
#define TRACE_ID_STRING_SIZE 32
#define SPAN_ID_SIZE 8
#define SPAN_ID_STRING_SIZE 16

#define BASE_SPAN_PROPERTIES \
    u64 start_time;          \
    u64 end_time;            \
    struct span_context sc;  \
    struct span_context psc; 

// Common flow for uprobe return:
// 1. Find consistend key for the current uprobe context
// 2. Use the key to lookup for the uprobe context in the uprobe_context_map
// 3. Update the end time of the found span
// 4. Submit the constructed event to the agent code using perf buffer events_map
// 5. Delete the span from the uprobe_context_map
// 6. Delete the span from the global active spans map
#define UPROBE_RETURN(name, event_type, ctx_struct_pos, ctx_struct_offset, uprobe_context_map, events_map) \
SEC("uprobe/##name##")                                                                                     \
int uprobe_##name##_Returns(struct pt_regs *ctx) {                                                         \
    void *req_ptr = get_argument(ctx, ctx_struct_pos);                                                     \
    void *key = get_consistent_key(ctx, (void *)(req_ptr + ctx_struct_offset));                            \
    void *req_ptr_map = bpf_map_lookup_elem(&uprobe_context_map, &key);                                    \
    event_type tmpReq = {};                                                                                \
    bpf_probe_read(&tmpReq, sizeof(tmpReq), req_ptr_map);                                                  \
    tmpReq.end_time = bpf_ktime_get_ns();                                                                  \
    bpf_perf_event_output(ctx, &events_map, BPF_F_CURRENT_CPU, &tmpReq, sizeof(tmpReq));                   \
    bpf_map_delete_elem(&uprobe_context_map, &key);                                                        \
    stop_tracking_span(&tmpReq.sc);                                                                        \
    return 0;                                                                                              \
}

struct sql_request_t {
    BASE_SPAN_PROPERTIES
    char query[MAX_QUERY_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void*);
	__type(value, struct sql_request_t);
	__uint(max_entries, MAX_CONCURRENT);
} sql_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Injected in init
volatile const bool should_include_db_statement;

// This instrumentation attaches uprobe to the following function:
// func (db *DB) queryDC(ctx, txctx context.Context, dc *driverConn, releaseConn func(error), query string, args []any)
SEC("uprobe/queryDC")
int uprobe_queryDC(struct pt_regs *ctx) {
    // argument positions
    u64 context_ptr_pos = 3;
    u64 query_str_ptr_pos = 8;
    u64 query_str_len_pos = 9;

    struct sql_request_t sql_request = {0};
    sql_request.start_time = bpf_ktime_get_ns();

    if (should_include_db_statement) {
        // Read Query string
        void *query_str_ptr = get_argument(ctx, query_str_ptr_pos);
        u64 query_str_len = (u64)get_argument(ctx, query_str_len_pos);
        u64 query_size = MAX_QUERY_SIZE < query_str_len ? MAX_QUERY_SIZE : query_str_len;
        bpf_probe_read(sql_request.query, query_size, query_str_ptr);
    }

    // Get parent if exists
    void *context_ptr = get_argument(ctx, context_ptr_pos);
    void *context_ptr_val = 0;
    bpf_probe_read(&context_ptr_val, sizeof(context_ptr_val), context_ptr);
    struct span_context *span_ctx = get_parent_span_context(context_ptr_val);
    if (span_ctx != NULL) {
        // Set the parent context
        bpf_probe_read(&sql_request.psc, sizeof(sql_request.psc), span_ctx);
        copy_byte_arrays(sql_request.psc.TraceID, sql_request.sc.TraceID, TRACE_ID_SIZE);
        generate_random_bytes(sql_request.sc.SpanID, SPAN_ID_SIZE);
    } else {
        sql_request.sc = generate_span_context();
    }

    // Get key
    void *key = get_consistent_key(ctx, context_ptr);

    bpf_map_update_elem(&sql_events, &key, &sql_request, 0);
    start_tracking_span(context_ptr_val, &sql_request.sc);
    return 0;
}

// This instrumentation attaches uprobe to the following function:
// func (db *DB) queryDC(ctx, txctx context.Context, dc *driverConn, releaseConn func(error), query string, args []any)
UPROBE_RETURN(queryDC, struct sql_request_t, 3, 0, sql_events, events)