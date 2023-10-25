// Inspired by https://github.com/open-telemetry/opentelemetry-go-instrumentation/blob/ca1afccea6ec520d18238c3865024a9f5b9c17fe/internal/pkg/instrumentors/bpf/database/sql/bpf/probe.bpf.c
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
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "go_common.h"
#include "bpf_dbg.h"
#include <stdbool.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, func_invocation);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_sql_queries SEC(".maps");

SEC("uprobe/queryDC")
int uprobe_queryDC(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/queryDC === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    func_invocation invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .regs = *ctx,
    };

    // Write event
    if (bpf_map_update_elem(&ongoing_sql_queries, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }

    return 0;
}

SEC("uprobe/queryDC")
int uprobe_queryDCReturn(struct pt_regs *ctx) {

    bpf_dbg_printk("=== uprobe/queryDCReturn === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    func_invocation *invocation = bpf_map_lookup_elem(&ongoing_sql_queries, &goroutine_addr);
    if (invocation == NULL) {
        bpf_dbg_printk("Request not found for this goroutine");
        return 0;
    }
    bpf_map_delete_elem(&ongoing_sql_queries, &goroutine_addr);

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (trace) {
        task_pid((struct task_struct *)bpf_get_current_task(), &trace->pid);
        trace->type = EVENT_SQL_CLIENT;
        trace->id = (u64)goroutine_addr;
        trace->start_monotime_ns = invocation->start_monotime_ns;
        trace->end_monotime_ns = bpf_ktime_get_ns();
        u64 query_len = (u64)GO_PARAM9(&(invocation->regs));
        if (query_len > sizeof(trace->path)) {
            query_len = sizeof(trace->path);
        }
        bpf_probe_read(trace->path, query_len, (void*)GO_PARAM8(&(invocation->regs)));
        // submit the completed trace via ringbuffer
        bpf_ringbuf_submit(trace, get_flags());
    } else {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
    }
    return 0;
}