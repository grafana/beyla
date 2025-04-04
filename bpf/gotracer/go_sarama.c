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

#include <bpfcore/utils.h>

#include <common/ringbuf.h>

#include <gotracer/go_common.h>
#include <gotracer/go_kafka_def.h>

#include <logger/bpf_dbg.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: correlation id
    __type(value, kafka_client_req_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} kafka_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: goroutine id
    __type(value, u32);         // correlation id
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_kafka_requests SEC(".maps");

SEC("uprobe/sarama_sendInternal")
int beyla_uprobe_sarama_sendInternal(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/sarama_sendInternal === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    void *b_ptr = GO_PARAM1(ctx);
    off_table_t *ot = get_offsets_table();

    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    u32 correlation_id = 0;

    if (b_ptr) {
        bpf_probe_read(&correlation_id,
                       sizeof(u32),
                       b_ptr + go_offset_of(ot, (go_offset){.v = _sarama_broker_corr_id_pos}));
    }

    if (correlation_id) {
        bpf_dbg_printk("correlation_id = %d", correlation_id);

        if (bpf_map_update_elem(&ongoing_kafka_requests, &g_key, &correlation_id, BPF_ANY)) {
            bpf_dbg_printk("can't update kafka requests element");
        }
    }

    return 0;
}

SEC("uprobe/sarama_broker_write")
int beyla_uprobe_sarama_broker_write(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/sarama_broker write === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);

    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    u32 *invocation = bpf_map_lookup_elem(&ongoing_kafka_requests, &g_key);
    void *b_ptr = GO_PARAM1(ctx);
    void *buf_ptr = GO_PARAM2(ctx);
    off_table_t *ot = get_offsets_table();

    if (invocation) {
        u8 small_buf[8];
        bpf_probe_read(small_buf, 8, buf_ptr);
        // the api key is 2 bytes, but num APIs at the moment is max 50.
        // instead of reading 2 bytes and then doing ntohs, we just read
        // the second byte of the api key, assuming the first is 0.
        u8 api_key = small_buf[KAFKA_API_KEY_POS];

        bpf_dbg_printk("api_key = %d", api_key);

        // We only care about fetch and produce
        if (api_key == KAFKA_API_FETCH || api_key == KAFKA_API_PRODUCE) {
            u32 correlation_id = *invocation;
            kafka_client_req_t req = {
                .type = EVENT_GO_KAFKA,
                .start_monotime_ns = bpf_ktime_get_ns(),
            };

            void *conn_conn_ptr =
                (void *)(b_ptr + go_offset_of(ot, (go_offset){.v = _sarama_broker_conn_pos}));
            bpf_dbg_printk("conn conn ptr %llx", conn_conn_ptr);
            if (conn_conn_ptr) {
                void *tcp_conn_ptr = 0;
                bpf_probe_read(
                    &tcp_conn_ptr,
                    sizeof(tcp_conn_ptr),
                    (void *)(conn_conn_ptr +
                             go_offset_of(ot, (go_offset){.v = _sarama_bufconn_conn_pos}) +
                             8)); // find conn
                bpf_dbg_printk("tcp conn ptr %llx", tcp_conn_ptr);
                if (tcp_conn_ptr) {
                    void *conn_ptr = 0;
                    bpf_probe_read(
                        &conn_ptr, sizeof(conn_ptr), (void *)(tcp_conn_ptr + 8)); // find conn
                    bpf_dbg_printk("conn ptr %llx", conn_ptr);
                    if (conn_ptr) {
                        u8 ok = get_conn_info(conn_ptr, &req.conn);
                        if (!ok) {
                            __builtin_memset(&req.conn, 0, sizeof(connection_info_t));
                        }
                    }
                }
            }

            bpf_dbg_printk("correlation_id = %d", correlation_id);

            bpf_probe_read(req.buf, KAFKA_MAX_LEN, buf_ptr);
            go_addr_key_t k_key = {};
            go_addr_key_from_id(&k_key, (void *)(uintptr_t)correlation_id);
            bpf_map_update_elem(&kafka_requests, &k_key, &req, BPF_ANY);
        }
    }

    bpf_map_delete_elem(&ongoing_kafka_requests, &g_key);

    return 0;
}

SEC("uprobe/sarama_response_promise_handle")
int beyla_uprobe_sarama_response_promise_handle(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/sarama_response_promise_handle === ");

    void *p = GO_PARAM1(ctx);
    off_table_t *ot = get_offsets_table();

    if (p) {
        u32 correlation_id = 0;

        bpf_probe_read(&correlation_id,
                       sizeof(u32),
                       p + go_offset_of(ot, (go_offset){.v = _sarama_response_corr_id_pos}));

        bpf_dbg_printk("correlation_id = %d", correlation_id);

        if (correlation_id) {
            go_addr_key_t k_key = {};
            go_addr_key_from_id(&k_key, (void *)(uintptr_t)correlation_id);
            kafka_client_req_t *req = bpf_map_lookup_elem(&kafka_requests, &k_key);

            if (req) {
                req->end_monotime_ns = bpf_ktime_get_ns();

                kafka_client_req_t *trace =
                    bpf_ringbuf_reserve(&events, sizeof(kafka_client_req_t), 0);
                if (trace) {
                    bpf_dbg_printk("Sending kafka client go trace");

                    __builtin_memcpy(trace, req, sizeof(kafka_client_req_t));
                    task_pid(&trace->pid);
                    bpf_ringbuf_submit(trace, get_flags());
                }
            }
            bpf_map_delete_elem(&kafka_requests, &k_key);
        }
    }

    return 0;
}
