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
#include "go_str.h"
#include "go_byte_arr.h"
#include "bpf_dbg.h"
#include "go_common.h"

typedef struct grpc_method_data_t {
    u64 start_monotime_ns;
    u64 status;          // we only need u16, but regs below must be 8-byte aligned
    struct pt_regs regs; // we store registers on invocation to be able to fetch the arguments at return
} grpc_method_data;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, grpc_method_data);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_requests SEC(".maps");

// To be Injected from the user space during the eBPF program load & initialization

volatile const u64 grpc_stream_st_ptr_pos;
volatile const u64 grpc_stream_method_ptr_pos;
volatile const u64 grpc_status_s_pos;
volatile const u64 grpc_status_code_ptr_pos;
volatile const u64 grpc_st_remoteaddr_ptr_pos;
volatile const u64 grpc_st_localaddr_ptr_pos;
volatile const u64 tcp_addr_port_ptr_pos;
volatile const u64 tcp_addr_ip_ptr_pos;


SEC("uprobe/server_handleStream")
int uprobe_server_handleStream(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/server_handleStream === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    grpc_method_data invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .regs = *ctx,
        .status = -1
    };

    if (bpf_map_update_elem(&ongoing_grpc_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update grpc map element");
    }

    return 0;
}

SEC("uprobe/server_handleStream")
int uprobe_server_handleStream_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/server_handleStream return === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    grpc_method_data *invocation =
        bpf_map_lookup_elem(&ongoing_grpc_requests, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_grpc_requests, &goroutine_addr);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read grpc invocation metadata");
        return 0;
    }

    void *stream_ptr = GO_PARAM4(&(invocation->regs));
    bpf_dbg_printk("stream_ptr %lx, method pos %lx", stream_ptr, grpc_stream_method_ptr_pos);

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        return 0;
    }
    trace->type = EVENT_GRPC_REQUEST;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->status = invocation->status;

    u64 *go_start_monotime_ns = bpf_map_lookup_elem(&ongoing_goroutines, &goroutine_addr);
    if (go_start_monotime_ns) {
        trace->go_start_monotime_ns = *go_start_monotime_ns;
        bpf_map_delete_elem(&ongoing_goroutines, &goroutine_addr);
    } else {
        trace->go_start_monotime_ns = invocation->start_monotime_ns;
    }

    // Get method from transport.Stream.Method
    if (!read_go_str("grpc method", stream_ptr, grpc_stream_method_ptr_pos, &trace->path, sizeof(trace->path))) {
        bpf_printk("can't read grpc transport.Stream.Method");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    void *st_ptr = 0;
    // Read the embedded object ptr
    bpf_probe_read(&st_ptr, sizeof(st_ptr), (void *)(stream_ptr + grpc_stream_st_ptr_pos + sizeof(void *)));

    if (st_ptr) {
        void *peer_ptr = 0; 
        bpf_probe_read(&peer_ptr, sizeof(peer_ptr), (void *)(st_ptr + grpc_st_remoteaddr_ptr_pos + sizeof(void *)));

        if (peer_ptr) {
            u64 remote_addr_len = 0;
            if (!read_go_byte_arr("grpc peer ptr", peer_ptr, tcp_addr_ip_ptr_pos, &trace->remote_addr, &remote_addr_len, sizeof(trace->remote_addr))) {
                bpf_printk("can't read grpc peer ptr");
                bpf_ringbuf_discard(trace, 0);
                return 0;
            }
            trace->remote_addr_len = remote_addr_len;
        }

        void *host_ptr = 0;
        bpf_probe_read(&host_ptr, sizeof(host_ptr), (void *)(st_ptr + grpc_st_localaddr_ptr_pos + sizeof(void *)));

        if (host_ptr) {
            u64 host_len = 0;

            if (!read_go_byte_arr("grpc host ptr", host_ptr, tcp_addr_ip_ptr_pos, &trace->host, &host_len,  sizeof(trace->host))) {
                bpf_printk("can't read grpc host ptr");
                bpf_ringbuf_discard(trace, 0);
                return 0;
            }
            trace->host_len = host_len;

            bpf_probe_read(&trace->host_port, sizeof(trace->host_port), (void *)(host_ptr + tcp_addr_port_ptr_pos));
        }
    }

    trace->end_monotime_ns = bpf_ktime_get_ns();
    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

    return 0;
}

SEC("uprobe/transport_writeStatus")
int uprobe_transport_writeStatus(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/transport_writeStatus === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    grpc_method_data *invocation =
        bpf_map_lookup_elem(&ongoing_grpc_requests, &goroutine_addr);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read grpc invocation metadata in write status");
        return 0;
    }

    void *status_ptr = GO_PARAM3(ctx);
    bpf_dbg_printk("status_ptr %lx", status_ptr);

    if (status_ptr != NULL) {
        void *s_ptr;
        bpf_probe_read(&s_ptr, sizeof(s_ptr), (void *)(status_ptr + grpc_status_s_pos));

        bpf_dbg_printk("s_ptr %lx", s_ptr);

        if (s_ptr != NULL) {
            bpf_probe_read(&invocation->status, sizeof(invocation->status), (void *)(s_ptr + grpc_status_code_ptr_pos));
            bpf_dbg_printk("status code %d", invocation->status);
            bpf_map_update_elem(&ongoing_grpc_requests, &goroutine_addr, invocation, BPF_ANY);
        }
    }

    return 0;
}
