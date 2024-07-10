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

#define KAFKA_API_FETCH   1
#define KAFKA_API_PRODUCE 0

volatile const u64 kafka_go_writer_topic_pos;
volatile const u64 kafka_go_protocol_conn_pos;
volatile const u64 kafka_go_reader_topic_pos;

typedef struct produce_req {
    u64 msg_ptr;
    u64 conn_ptr;
    u64 start_monotime_ns;
} produce_req_t;

typedef struct topic {
    char name[MAX_TOPIC_NAME_LEN];
} topic_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // goroutine
    __type(value, topic_t); // topic info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_produce_topics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // msg ptr
    __type(value, topic_t); // topic info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_produce_messages SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // goroutine
    __type(value, produce_req_t); // rw ptr + start time
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} produce_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // goroutine
    __type(value, kafka_go_req_t); // rw ptr + start time
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} fetch_requests SEC(".maps");

// Code for the produce messages path
SEC("uprobe/writer_produce")
int uprobe_writer_produce(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/kafka-go writer_produce %llx === ", goroutine_addr);

    void *w_ptr = (void *)GO_PARAM1(ctx);

    if (w_ptr) {
        void *topic_ptr = 0;
        bpf_probe_read_user(&topic_ptr, sizeof(void *), w_ptr + kafka_go_writer_topic_pos);

        bpf_dbg_printk("topic_ptr %llx", topic_ptr);
        if (topic_ptr) {
            topic_t topic = {};
            bpf_probe_read_user(&topic.name, sizeof(topic.name), topic_ptr);
            bpf_map_update_elem(&ongoing_produce_topics, &goroutine_addr, &topic, BPF_ANY);
        }
    }

    // TODO: Since we can find the relationship from the originating goroutine, we can set the traceparent.
    // Add it to topic_t.

    return 0;
}

SEC("uprobe/client_roundTrip")
int uprobe_client_roundTrip(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/kafka-go client_roundTrip %llx === ", goroutine_addr);

    topic_t *topic_ptr = bpf_map_lookup_elem(&ongoing_produce_topics, &goroutine_addr);

    if (topic_ptr) {
        void *msg_ptr = (void *)GO_PARAM7(ctx);
        bpf_dbg_printk("msg ptr %llx", msg_ptr);
        if (msg_ptr) {
            topic_t topic;
            __builtin_memcpy(&topic, topic_ptr, sizeof(topic_t));
            bpf_map_update_elem(&ongoing_produce_messages, &msg_ptr, &topic, BPF_ANY);
        }
    }

    bpf_map_delete_elem(&ongoing_produce_topics, &goroutine_addr);
    return 0;
}

SEC("uprobe/protocol_RoundTrip")
int uprobe_protocol_roundtrip(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/kafka-go protocol_RoundTrip === ");
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    void *rw_ptr = (void *)GO_PARAM2(ctx);
    void *msg_ptr = (void *)GO_PARAM8(ctx);
    bpf_dbg_printk("goroutine_addr %lx, rw ptr %llx, msg_ptr %llx", goroutine_addr, rw_ptr, msg_ptr);


    if (rw_ptr) {
        topic_t *topic_ptr = bpf_map_lookup_elem(&ongoing_produce_messages, &msg_ptr);
        bpf_dbg_printk("Found topic %llx", topic_ptr);
        if (topic_ptr) {
            produce_req_t p = {
                .conn_ptr = ((u64)rw_ptr) + kafka_go_protocol_conn_pos,
                .msg_ptr = (u64)msg_ptr,
                .start_monotime_ns = bpf_ktime_get_ns(),
            };

            bpf_map_update_elem(&produce_requests, &goroutine_addr, &p, BPF_ANY);
        }
    }

    return 0;
}

SEC("uprobe/protocol_RoundTrip_ret")
int uprobe_protocol_roundtrip_ret(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/protocol_RoundTrip ret %llx === ", goroutine_addr);
    
    produce_req_t *p_ptr = bpf_map_lookup_elem(&produce_requests, &goroutine_addr);

    bpf_dbg_printk("p_ptr %llx", p_ptr);

    if (p_ptr) {
        void *msg_ptr = (void *)p_ptr->msg_ptr;
        topic_t *topic_ptr = bpf_map_lookup_elem(&ongoing_produce_messages, &msg_ptr);

        bpf_dbg_printk("goroutine_addr %lx, conn ptr %llx, msg_ptr = %llx, topic_ptr = %llx", goroutine_addr, p_ptr->conn_ptr, p_ptr->msg_ptr, topic_ptr);

        if (topic_ptr) {
            kafka_go_req_t *trace = bpf_ringbuf_reserve(&events, sizeof(kafka_go_req_t), 0);
            if (trace) {
                trace->type = EVENT_GO_KAFKA_SEG;
                trace->op = KAFKA_API_PRODUCE;
                trace->start_monotime_ns = p_ptr->start_monotime_ns;
                trace->end_monotime_ns = bpf_ktime_get_ns();

                void *conn_ptr = 0;
                bpf_probe_read(&conn_ptr, sizeof(conn_ptr), (void *)(p_ptr->conn_ptr + 8)); // find conn
                bpf_dbg_printk("conn ptr %llx", conn_ptr);
                if (conn_ptr) {
                    get_conn_info(conn_ptr, &trace->conn);
                }

                bpf_probe_read(trace->topic, MAX_TOPIC_NAME_LEN, ((void *)topic_ptr->name));
                task_pid(&trace->pid);
                bpf_ringbuf_submit(trace, get_flags());
            }
        }
        bpf_map_delete_elem(&ongoing_produce_messages, &msg_ptr);
    }

    bpf_map_delete_elem(&produce_requests, &goroutine_addr);

    return 0;
}


// Code for the fetch messages path
SEC("uprobe/reader_read")
int uprobe_reader_read(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    void *r_ptr = (void *)GO_PARAM1(ctx);
    void *conn = (void *)GO_PARAM5(ctx);
    bpf_printk("=== uprobe/kafka-go reader_read %llx r_ptr %llx=== ", goroutine_addr, r_ptr);

    if (r_ptr) {
        kafka_go_req_t r = {
            .type = EVENT_GO_KAFKA_SEG,
            .op = KAFKA_API_FETCH,
            .start_monotime_ns = 0,
        };

        void *topic_ptr = 0;
        bpf_probe_read_user(&topic_ptr, sizeof(void *), r_ptr + kafka_go_reader_topic_pos);

        bpf_dbg_printk("topic_ptr %llx", topic_ptr);
        if (topic_ptr) {
            bpf_probe_read_user(&r.topic, sizeof(r.topic), topic_ptr);
        }

        if (conn) {
            void *conn_ptr = 0;
            bpf_probe_read(&conn_ptr, sizeof(conn_ptr), (void *)(conn + 8)); // find conn
            bpf_dbg_printk("conn ptr %llx", conn_ptr);
            if (conn_ptr) {
                get_conn_info(conn_ptr, &r.conn);
            }
        }

        bpf_map_update_elem(&fetch_requests, &goroutine_addr, &r, BPF_ANY);
    }

    return 0;
}

SEC("uprobe/reader_send_message")
int uprobe_reader_send_message(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/kafka-go reader_send_message %llx === ", goroutine_addr);

    kafka_go_req_t *req = (kafka_go_req_t *)bpf_map_lookup_elem(&fetch_requests, &goroutine_addr);
    bpf_dbg_printk("Found req_ptr %llx", req);

    if (req) {
        req->start_monotime_ns = bpf_ktime_get_ns();
    }

    return 0;
}

SEC("uprobe/reader_read")
int uprobe_reader_read_ret(struct pt_regs *ctx) {
    void *goroutine_addr = (void *)GOROUTINE_PTR(ctx);
    bpf_dbg_printk("=== uprobe/kafka-go reader_read ret %llx === ", goroutine_addr);

    kafka_go_req_t *req = (kafka_go_req_t *)bpf_map_lookup_elem(&fetch_requests, &goroutine_addr);
    bpf_dbg_printk("Found req_ptr %llx", req);

    if (req) {
        if (req->start_monotime_ns) {
            kafka_go_req_t *trace = bpf_ringbuf_reserve(&events, sizeof(kafka_go_req_t), 0);
            if (trace) {
                __builtin_memcpy(trace, req, sizeof(kafka_go_req_t));
                trace->end_monotime_ns = bpf_ktime_get_ns();
                task_pid(&trace->pid);
                bpf_ringbuf_submit(trace, get_flags());
            }
        } else {
            bpf_dbg_printk("Found request with no start time, ignoring...");
        }
    }

    bpf_map_delete_elem(&fetch_requests, &goroutine_addr);

    return 0;
}