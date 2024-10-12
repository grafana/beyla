// Copyright The OpenTelemetry Authors
// Copyright Grafana Labs
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

// This implementation was inspired by https://github.com/open-telemetry/opentelemetry-go-instrumentation/blob/ca1afccea6ec520d18238c3865024a9f5b9c17fe/internal/pkg/instrumentors/bpf/database/sql/bpf/probe.bpf.c
// and has been modified since.

#ifndef GO_SQL_H
#define GO_SQL_H

#include "vmlinux.h"

#include "bpf_helpers.h"
#include "http_types.h"
#include "go_common.h"
#include "ringbuf.h"

typedef struct sql_func_invocation {
    u64 start_monotime_ns;
    u64 sql_param;
    u64 query_len;
    connection_info_t conn __attribute__((aligned(8)));
    tp_info_t tp;
} sql_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, sql_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_sql_queries SEC(".maps");

static __always_inline void set_sql_info(void *goroutine_addr, void *sql_param, void *query_len) {
    sql_func_invocation_t invocation = {.start_monotime_ns = bpf_ktime_get_ns(),
                                        .sql_param = (u64)sql_param,
                                        .query_len = (u64)query_len,
                                        .tp = {0}};

    // We don't look up in the headers, no http/grpc request, therefore 0 as last argument
    client_trace_parent(goroutine_addr, &invocation.tp, 0);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    // Write event
    if (bpf_map_update_elem(&ongoing_sql_queries, &g_key, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }
}

SEC("uprobe/queryDC")
int uprobe_queryDC(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/queryDC === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *sql_param = GO_PARAM8(ctx);
    void *query_len = GO_PARAM9(ctx);

    off_table_t *ot = get_offsets_table();
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    connection_info_t *existing = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);

    if (!existing) {
        void *c_ptr = GO_PARAM1(ctx);
        if (c_ptr) {
            void *conn_conn_ptr =
                c_ptr + 8 + go_offset_of(ot, (go_offset){.v = _c_rwc_pos}); // embedded struct
            void *tls_state = 0;
            bpf_probe_read(&tls_state,
                           sizeof(tls_state),
                           (void *)(c_ptr + go_offset_of(ot, (go_offset){.v = _c_tls_pos})));
            conn_conn_ptr = unwrap_tls_conn_info(conn_conn_ptr, tls_state);
            //bpf_dbg_printk("conn_conn_ptr %llx, tls_state %llx, c_tls_pos = %d, c_tls_ptr = %llx", conn_conn_ptr, tls_state, c_tls_pos, c_ptr + c_tls_pos);
            if (conn_conn_ptr) {
                void *conn_ptr = 0;
                bpf_probe_read(
                    &conn_ptr,
                    sizeof(conn_ptr),
                    (void *)(conn_conn_ptr +
                             go_offset_of(ot, (go_offset){.v = _net_conn_pos}))); // find conn
                bpf_dbg_printk("conn_ptr %llx", conn_ptr);
                if (conn_ptr) {
                    connection_info_t conn = {0};
                    get_conn_info(
                        conn_ptr,
                        &conn); // initialized to 0, no need to check the result if we succeeded
                    bpf_map_update_elem(&ongoing_server_connections, &g_key, &conn, BPF_ANY);
                }
            }
        }
    }

    set_sql_info(goroutine_addr, sql_param, query_len);
    return 0;
}

SEC("uprobe/execDC")
int uprobe_execDC(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/execDC === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *sql_param = GO_PARAM6(ctx);
    void *query_len = GO_PARAM7(ctx);
    set_sql_info(goroutine_addr, sql_param, query_len);
    return 0;
}

SEC("uprobe/queryDC")
int uprobe_queryReturn(struct pt_regs *ctx) {

    bpf_dbg_printk("=== uprobe/query return === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    sql_func_invocation_t *invocation = bpf_map_lookup_elem(&ongoing_sql_queries, &g_key);
    if (invocation == NULL) {
        bpf_dbg_printk("Request not found for this goroutine");
        return 0;
    }
    bpf_map_delete_elem(&ongoing_sql_queries, &g_key);

    sql_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(sql_request_trace), 0);
    if (trace) {
        task_pid(&trace->pid);
        trace->type = EVENT_SQL_CLIENT;
        trace->start_monotime_ns = invocation->start_monotime_ns;
        trace->end_monotime_ns = bpf_ktime_get_ns();

        void *resp_ptr = GO_PARAM1(ctx);
        trace->status = (resp_ptr == NULL);
        trace->tp = invocation->tp;

        u64 query_len = invocation->query_len;
        if (query_len > sizeof(trace->sql)) {
            query_len = sizeof(trace->sql);
        }
        bpf_probe_read(trace->sql, query_len, (void *)invocation->sql_param);
        bpf_dbg_printk("Found sql statement %s", trace->sql);
        if (query_len < sizeof(trace->sql)) {
            trace->sql[query_len] = 0;
        }

        connection_info_t *info = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);

        if (info) {
            //dbg_print_http_connection_info(info);
            __builtin_memcpy(&trace->conn, info, sizeof(connection_info_t));
        } else {
            // We can't find the connection info, this typically means there are too many requests per second
            // and the connection map is too small for the workload.
            bpf_dbg_printk("Can't find connection info for %llx", goroutine_addr);
            __builtin_memset(&trace->conn, 0, sizeof(connection_info_t));
        }

        // Server connections have opposite order, source port is the server port
        swap_connection_info_order(&trace->conn);

        // submit the completed trace via ringbuffer
        bpf_ringbuf_submit(trace, get_flags());
    } else {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
    }
    return 0;
}

#endif
