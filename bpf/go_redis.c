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
#include "bpf_dbg.h"
#include "go_common.h"
#include "ringbuf.h"

volatile const u64 redis_broker_corr_id_pos;
volatile const u64 redis_response_corr_id_pos;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: goroutine id
    __type(value, redis_client_req_t); // the request
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_redis_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: goroutine id
    __type(value, void *); // the *Conn
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} redis_writes SEC(".maps");

// github.com/redis/go-redis/v9.(*baseClient)._process
// func (c *baseClient) _process(ctx context.Context, cmd Cmder, attempt int) (bool, error) {
SEC("uprobe/redis_process")
int uprobe_redis_process(struct pt_regs *ctx) {
    bpf_printk("=== uprobe/redis _process === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_printk("goroutine_addr %lx", goroutine_addr);

    redis_client_req_t req = {
        .type = EVENT_GO_REDIS,
        .start_monotime_ns = bpf_ktime_get_ns(),
    };

    // We don't look up in the headers, no http/grpc request, therefore 0 as last argument
    client_trace_parent(goroutine_addr, &req.tp, 0);

    bpf_map_update_elem(&ongoing_redis_requests, &goroutine_addr, &req, BPF_ANY);

    return 0;
}

SEC("uprobe/redis_process")
int uprobe_redis_process_ret(struct pt_regs *ctx) {
    bpf_printk("=== uprobe/redis _process returns === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_printk("goroutine_addr %lx", goroutine_addr);

    redis_client_req_t *req = bpf_map_lookup_elem(&ongoing_redis_requests, &goroutine_addr);
    if (req) {
        redis_client_req_t *trace = bpf_ringbuf_reserve(&events, sizeof(redis_client_req_t), 0);        
        if (trace) {
            bpf_dbg_printk("Sending redis client go trace");
            __builtin_memcpy(trace, req, sizeof(redis_client_req_t));
            trace->end_monotime_ns = bpf_ktime_get_ns();
            bpf_ringbuf_submit(trace, get_flags());
        }
    }

    bpf_map_delete_elem(&ongoing_redis_requests, &goroutine_addr);

    return 0;
}

// github.com/redis/go-redis/v9/internal/pool.(*Conn).WithWriter
// func (cn *Conn) WithWriter(
//	ctx context.Context, timeout time.Duration, fn func(wr *proto.Writer) error,
// ) error
SEC("uprobe/redis_with_writer")
int uprobe_redis_with_writer(struct pt_regs *ctx) {
    bpf_printk("=== uprobe/redis WithWriter === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_printk("goroutine_addr %lx", goroutine_addr);

    redis_client_req_t *req = bpf_map_lookup_elem(&ongoing_redis_requests, &goroutine_addr);

    if (req) {
        void *cn_ptr = GO_PARAM1(ctx);

        void *bw_ptr = 0;

        bpf_probe_read(&bw_ptr, sizeof(void *), cn_ptr + 0x20);
        bpf_printk("bw_ptr %llx", bw_ptr);

        bpf_map_update_elem(&redis_writes, &goroutine_addr, &bw_ptr, BPF_ANY);

        if (cn_ptr) {
            void *tcp_conn_ptr = cn_ptr + 8;
            bpf_dbg_printk("tcp conn ptr %llx", tcp_conn_ptr);
            if (tcp_conn_ptr) {
                void *conn_ptr = 0;
                bpf_probe_read(&conn_ptr, sizeof(conn_ptr), (void *)(tcp_conn_ptr + 8)); // find conn
                bpf_dbg_printk("conn ptr %llx", conn_ptr);
                if (conn_ptr) {
                    get_conn_info_from_fd(conn_ptr, &req->conn);
                }
            }
        }
    }

    return 0;
}

SEC("uprobe/redis_with_writer")
int uprobe_redis_with_writer_ret(struct pt_regs *ctx) {
    bpf_printk("=== uprobe/redis WithWriter returns === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_printk("goroutine_addr %lx", goroutine_addr);

    redis_client_req_t *req = bpf_map_lookup_elem(&ongoing_redis_requests, &goroutine_addr);

    if (req) {
        void **bw_ptr = bpf_map_lookup_elem(&redis_writes, &goroutine_addr);

        if (bw_ptr) {
            void *bw = *bw_ptr;
            if (bw) {
                bpf_printk("Found bw %llx", bw);

                void *buf = 0;
                bpf_probe_read(&buf, sizeof(void *), bw + 0x10);
                u64 len = 0;

                bpf_probe_read(&len, sizeof(u64), bw + 0x18);

                bpf_printk("buf %llx[%s], len=%ld", buf, buf, len);

                if (len > 0) {
                    bpf_probe_read(&req->buf, REDIS_MAX_LEN, buf);
                }
            }
        }
    }
    return 0;
}
