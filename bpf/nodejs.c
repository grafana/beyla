#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_dbg.h"
#include "pid.h"
#include "ringbuf.h"

char __license[] SEC("license") = "Dual MIT/GPL";

volatile const s32 async_wrap_async_id_off = 0;
volatile const s32 async_wrap_trigger_async_id_off = 0;

SEC("uprobe/node:EmitAsyncInit")
int emit_async_init(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_printk("=== uprobe EmitAsyncInit id=%d ===", id);

    return 0;
}

SEC("uprobe/node:AsyncReset")
int async_reset(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_printk("=== uprobe AsyncReset id=%d ===", id);

    return 0;
}
