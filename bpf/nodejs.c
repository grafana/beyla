#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_dbg.h"
#include "pid.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("uprobe/node:EmitAsyncInit")
int emit_async_init(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_printk("=== uprobe EmitAsyncInit id=%d ===", id);

    return 0;
}
