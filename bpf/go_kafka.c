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

#define KAFKA_API_FETCH   0
#define KAFKA_API_PRODUCE 1

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32); // key: correlation id
    __type(value, kafka_client_req_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} kafka_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: goroutine id
    __type(value, u32); // correlation id
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_kafka_requests SEC(".maps");

SEC("uprobe/sarama_sendInternal")
int uprobe_sarama_sendInternal(struct pt_regs *ctx) {
    bpf_printk("=== uprobe/sarama_sendInternal === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_printk("goroutine_addr %lx", goroutine_addr);

    u32 correlation_id = 0;
    
    void *b_ptr = GO_PARAM1(ctx);
    bpf_printk("**** b_ptr = %llx *****", b_ptr);
    if (b_ptr) {
        bpf_probe_read(&correlation_id, sizeof(u32), b_ptr + 0x28); // TODO: Offsets
    }

    if (correlation_id) {
        bpf_printk("**** correlation_id = %d *****", correlation_id);

        if (bpf_map_update_elem(&ongoing_kafka_requests, &goroutine_addr, &correlation_id, BPF_ANY)) {
            bpf_dbg_printk("can't update kafka requests element");
        }
    }

    return 0;
}

SEC("uprobe/sarama_broker_write")
int uprobe_sarama_broker_write(struct pt_regs *ctx) {
    bpf_printk("=== uprobe/sarama_broker write === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_printk("goroutine_addr %lx", goroutine_addr);

    u32 *invocation = bpf_map_lookup_elem(&ongoing_kafka_requests, &goroutine_addr);
    void *buf_ptr = GO_PARAM2(ctx);

    bpf_printk("**** invocation = %llx, ptr %llx *****", invocation, buf_ptr);

    if (invocation) {
        u8 small_buf[8];
        bpf_probe_read(small_buf, 8, buf_ptr);
        // the api key is 2 bytes, but num APIs at the moment is max 50.
        // instead of reading 2 bytes and then doing ntohs, we just read
        // the second byte of the api key, assuming the first is 0.
        u8 api_key = small_buf[5];

        bpf_printk("**** api_key = %d *****", api_key);

        // We only care about fetch and produce
        if (api_key == KAFKA_API_FETCH || api_key == KAFKA_API_PRODUCE) {
            u32 correlation_id = *invocation;
            kafka_client_req_t req = {
                .type = EVENT_GO_KAFKA,
                .start_monotime_ns = bpf_ktime_get_ns(),
            };

            bpf_printk("**** correlation_id = %d *****", correlation_id);

            bpf_probe_read(req.buf, KAFKA_MAX_LEN, buf_ptr);
            bpf_map_update_elem(&kafka_requests, &correlation_id, &req, BPF_ANY);
        }

    }

    bpf_map_delete_elem(&ongoing_kafka_requests, &goroutine_addr);

    return 0;
}

SEC("uprobe/sarama_response_promise_handle")
int uprobe_sarama_response_promise_handle(struct pt_regs *ctx) {
    bpf_printk("=== uprobe/sarama_reponse_promise_handle === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_printk("goroutine_addr %lx", goroutine_addr);

    void *p = GO_PARAM1(ctx);

    if (p) {
        u32 correlation_id = 0;

        bpf_probe_read(&correlation_id, sizeof(u32), p + 0x18); // TODO: Offsets

        bpf_printk("**** correlation_id = %d *****", correlation_id);

        if (correlation_id) {
            kafka_client_req_t *req = bpf_map_lookup_elem(&kafka_requests, &correlation_id);

            bpf_printk("**** req = %lld *****", req);

            if (req) {
                req->end_monotime_ns = bpf_ktime_get_ns();

                kafka_client_req_t *trace = bpf_ringbuf_reserve(&events, sizeof(kafka_client_req_t), 0);        
                if (trace) {
                    bpf_dbg_printk("Sending trace");

                    __builtin_memcpy(trace, req, sizeof(kafka_client_req_t));
                    bpf_ringbuf_submit(trace, get_flags());
                }
            }

            bpf_map_delete_elem(&kafka_requests, &correlation_id);
        }
    }

    return 0;
}