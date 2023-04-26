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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the goroutine
    __type(value, u64);  // value: timestamp of the goroutine creation
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_goroutines SEC(".maps");

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
int uprobe_proc_newproc1_ret(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc newproc1 returns === ");

    void *goroutine_addr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    u64 timestamp = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&ongoing_goroutines, &goroutine_addr, &timestamp, BPF_ANY)) {
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