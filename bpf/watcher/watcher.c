//go:build obi_bpf_ignore
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/sockaddr.h>
#include <common/tcp_info.h>

#include <logger/bpf_dbg.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define WATCH_BIND 0x1

typedef struct watch_info {
    u64 flags; // Must be fist we use it to tell what kind of packet we have on the ring buffer
    u64 payload;
} watch_info_t;

const watch_info_t *unused_2 __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} watch_events SEC(".maps");

SEC("kprobe/sys_bind")
int beyla_kprobe_sys_bind(struct pt_regs *ctx) {
    // unwrap the args because it's a sys call
    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    void *addr;
    bpf_probe_read(&addr, sizeof(void *), (void *)&PT_REGS_PARM2(__ctx));

    if (!addr) {
        return 0;
    }

    u16 port = get_sockaddr_port_user(addr);

    if (!port) {
        return 0;
    }

    watch_info_t *trace = bpf_ringbuf_reserve(&watch_events, sizeof(watch_info_t), 0);
    if (trace) {
        trace->flags = WATCH_BIND;
        trace->payload = port;
        bpf_dbg_printk("New port bound %d", trace->payload);

        bpf_ringbuf_submit(trace, 0);
    }

    return 0;
}
