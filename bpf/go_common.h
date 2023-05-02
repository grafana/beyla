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

#ifndef GO_COMMON_H
#define GO_COMMON_H

#include "utils.h"
#include "bpf_dbg.h"
#include "http_trace.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// TODO: make this user-configurable and modify the value from the userspace when
// loading the maps with the Cilium library
#define MAX_CONCURRENT_REQUESTS 500

// setting here the following map definitions without pinning them to a global namespace
// would lead that services running both HTTP and GRPC server would duplicate 
// the events ringbuffer and goroutines map.
// This is an edge inefficiency that allows us avoiding the gotchas of
// pinning maps to the global namespace (e.g. like not cleaning them up when
// the autoinstrumenter ends abruptly)
// https://ants-gitlab.inf.um.es/jorgegm/xdp-tutorial/-/blob/master/basic04-pinning-maps/README.org
// we can share them later if we find is worth not including code per duplicate
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");


// Temporary information about a function invocation. It stores the invocation time of a function
// as well as the value of registers at the invocation time. This way we can retrieve them at the
// return uprobes so we can know the values of the function arguments (which are passed as registers
// since Go 1.17).
// This element is created in the function start probe and stored in the ongoing_http_requests hashmaps.
// Then it is retrieved in the return uprobes and used to know the HTTP call duration as well as its
// attributes (method, path, and status code).
typedef struct func_invocation_t {
    u64 start_monotime_ns;
    struct pt_regs regs; // we store registers on invocation to be able to fetch the arguments at return
} func_invocation;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, func_invocation);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} newproc1 SEC(".maps");

typedef struct goroutine_metadata_t {
    u64 parent;
    u64 timestamp;
} goroutine_metadata;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the goroutine
    __type(value, goroutine_metadata);  // value: timestamp of the goroutine creation
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_goroutines SEC(".maps");


// Shared structure that keeps track of ongoing server requests, HTTP or gRPC
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, func_invocation);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ongoing_server_requests SEC(".maps");


// To be Injected from the user space during the eBPF program load & initialization

volatile const u32 wakeup_data_bytes;

// get_flags prevents waking the userspace process up on each ringbuf message.
// If wakeup_data_bytes > 0, it will wait until wakeup_data_bytes are accumulated
// into the buffer before waking the userspace.
static __always_inline long get_flags()
{
	long sz;

	if (!wakeup_data_bytes)
		return 0;

	sz = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA);
	return sz >= wakeup_data_bytes ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

SEC("uprobe/runtime_newproc1")
int uprobe_proc_newproc1(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc newproc1 === ");
    void *creator_goroutine = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("creator_goroutine_addr %lx", creator_goroutine);

    func_invocation invocation = {
        .regs = *ctx,
    };

    // Save the registers on invocation to be able to fetch the arguments at return of newproc1
    if (bpf_map_update_elem(&newproc1, &creator_goroutine, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }

    return 0;
}

SEC("uprobe/runtime_newproc1_return")
int uprobe_proc_newproc1_ret(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc newproc1 returns === ");
    void *creator_goroutine = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("creator_goroutine_addr %lx", creator_goroutine);

    // Lookup the newproc1 invocation metadata
    func_invocation *invocation =
        bpf_map_lookup_elem(&newproc1, &creator_goroutine);
    bpf_map_delete_elem(&newproc1, &creator_goroutine);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read newproc1 invocation metadata");
        return 0;
    }

    // The parent goroutine is the second argument of newproc1
    void *parent_goroutine = (void *)GO_PARAM2(&invocation->regs);
    bpf_dbg_printk("parent goroutine_addr %lx", parent_goroutine);

    // The result of newproc1 is the new goroutine
    void *goroutine_addr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    goroutine_metadata metadata = {
        .timestamp = bpf_ktime_get_ns(),
        .parent = (u64)parent_goroutine,
    };

    if (bpf_map_update_elem(&ongoing_goroutines, &goroutine_addr, &metadata, BPF_ANY)) {
        bpf_dbg_printk("can't update active goroutine");
    }

    return 0;
}

SEC("uprobe/runtime_goexit1")
int uprobe_proc_goexit1(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc goexit1 === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    bpf_map_delete_elem(&ongoing_goroutines, &goroutine_addr);

    return 0;
}


#endif // GO_COMMON_H