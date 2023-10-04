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

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "go_common.h"
#include "bpf_dbg.h"
#include <stdbool.h>

#define MAX_QUERY_SIZE 100

struct sql_request_t {
    u64 start_time;
    char query[MAX_QUERY_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void*);
	__type(value, struct sql_request_t);
	__uint(max_entries, MAX_CONCURRENT_REQUESTS);
} sql_events SEC(".maps");

// Injected in init
volatile const bool should_include_db_statement;

// This instrumentation attaches uprobe to the following function:
// func (db *DB) queryDC(ctx, txctx context.Context, dc *driverConn, releaseConn func(error), query string, args []any)
SEC("uprobe/queryDC")
int uprobe_queryDC(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/queryDC === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    struct sql_request_t sql_request = {0};
    sql_request.start_time = bpf_ktime_get_ns();

    if (1 /*  TODO: HOOK UP TO CONFIG */ || should_include_db_statement) {
        // Read Query string
        void *query_str_ptr = GO_PARAM8(ctx);
        u64 query_str_len = (u64)GO_PARAM9(ctx);
        u64 query_size = MAX_QUERY_SIZE < query_str_len ? MAX_QUERY_SIZE : query_str_len;
        bpf_probe_read(sql_request.query, query_size, query_str_ptr);
        bpf_dbg_printk("queryDC probe, size: %d, query: %100s", query_size, sql_request.query); // TODO: REMOVE ME
    } else {
        bpf_dbg_printk("queryDC probe, not including db statement"); // TODO: REMOVE ME
    }

    bpf_map_update_elem(&sql_events, &goroutine_addr, &sql_request, BPF_ANY);
    return 0;
}

SEC("uprobe/queryDC")
int uprobe_queryDC_Returns(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/queryDC_Returns === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    struct sql_request_t *request = bpf_map_lookup_elem(&sql_events, &goroutine_addr);
    if (request == NULL) {
        bpf_dbg_printk("Request not found for this goroutine");
        return 0;
    }

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (trace) {
        trace->type = EVENT_SQL_CLIENT;
        trace->id = (u64)goroutine_addr;
        trace->start_monotime_ns = request->start_time;
        trace->end_monotime_ns = bpf_ktime_get_ns();
        bpf_memcpy(trace->path, request->query, MAX_QUERY_SIZE);
        // submit the completed trace via ringbuffer
        bpf_ringbuf_submit(trace, get_flags());
    } else {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
    }
    bpf_map_delete_elem(&sql_events, &goroutine_addr);
    return 0;
}