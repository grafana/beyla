//go:build beyla_bpf_ignore
// Copyright (c) Meta Platforms, Inc. and affiliates.
// Copyright Grafana Labs
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "pid.h"
#include "bpf_dbg.h"
#include "gpuevent.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

const gpu_kernel_launch_t *unused_gpu __attribute__((unused));
const gpu_malloc_t *unused_gpu1 __attribute__((unused));

#define EVENT_GPU_KERNEL_LAUNCH 1
#define EVENT_GPU_MALLOC 2

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
} rb SEC(".maps");

const volatile struct {
    bool capture_args;
    bool capture_stack;
} prog_cfg = {
    // These defaults will be overridden from user space
    .capture_args = true,
    .capture_stack = true,
};

// The caller uses registers to pass the first 6 arguments to the callee.  Given
// the arguments in left-to-right order, the order of registers used is: %rdi,
// %rsi, %rdx, %rcx, %r8, and %r9. Any remaining arguments are passed on the
// stack in reverse order so that they can be popped off the stack in order.
#define SP_OFFSET(offset) (void *)PT_REGS_SP(ctx) + (offset * 8)

SEC("uprobe/cudaLaunchKernel")
int BPF_KPROBE(handle_cuda_launch,
               u64 func_off,
               u64 grid_xy,
               u64 grid_z,
               u64 block_xy,
               u64 block_z,
               uintptr_t argv) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== cudaLaunchKernel %llx ===", id);

    gpu_kernel_launch_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        bpf_dbg_printk("Failed to allocate ringbuf entry");
        return 0;
    }

    e->flags = EVENT_GPU_KERNEL_LAUNCH;
    task_pid(&e->pid_info);

    e->kern_func_off = func_off;
    e->grid_x = (u32)grid_xy;
    e->grid_y = (u32)(grid_xy >> 32);
    e->grid_z = (u32)grid_z;
    e->block_x = (u32)block_xy;
    e->block_y = (u32)(block_xy >> 32);
    e->block_z = (u32)block_z;

    bpf_probe_read_user(&e->stream, sizeof(uintptr_t), SP_OFFSET(2));

    if (prog_cfg.capture_args) {
        // Read the Cuda Kernel Launch Arguments
        for (int i = 0; i < MAX_GPUKERN_ARGS; i++) {
            const void *arg_addr;
            // We don't know how many argument this kernel has until we parse the
            // signature, so we always attemps to read the maximum number of args,
            // even if some of these arg values are not valid.
            bpf_probe_read_user(&arg_addr, sizeof(u64), (const void *)(argv + (i * sizeof(u64))));

            bpf_probe_read_user(&e->args[i], sizeof(arg_addr), arg_addr);
        }
    }

    if (prog_cfg.capture_stack) {
        // Read the Cuda Kernel Launch Stack
        e->ustack_sz =
            bpf_get_stack(ctx, e->ustack, sizeof(e->ustack), BPF_F_USER_STACK) / sizeof(uint64_t);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/cudaMalloc")
int BPF_KPROBE(handle_cuda_malloc, void **devPtr, size_t size) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== cudaMalloc %llx ===", id);

    gpu_malloc_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        bpf_dbg_printk("Failed to allocate ringbuf entry");
        return 0;
    }

    e->flags = EVENT_GPU_MALLOC;
    task_pid(&e->pid_info);
    e->size = (u64)size;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
