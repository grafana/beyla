#ifndef NODE_JS_H
#define NODE_JS_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_dbg.h"
#include "pid.h"
#include "ringbuf.h"
#include "map_sizing.h"
#include "pin_internal.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);          // the pid_tid
    __type(value, u64);        // the last active async_id
    __uint(max_entries, 1000); // 1000 nodejs services, small number, nodejs is single threaded
    __uint(pinning, BEYLA_PIN_INTERNAL);
} active_nodejs_ids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // child async_id
    __type(value, u64); // parent async_id
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} nodejs_parent_map SEC(".maps");

volatile const s32 async_wrap_async_id_off = 0;
volatile const s32 async_wrap_trigger_async_id_off = 0;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);          // the pid_tid
    __type(value, u64);        // the last AsyncWrap *
    __uint(max_entries, 1000); // 1000 nodejs services, small number, nodejs is single threaded
    __uint(pinning, BEYLA_PIN_INTERNAL);
} async_reset_args SEC(".maps");

SEC("uprobe/node:AsyncReset")
int beyla_async_reset(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    u64 wrap = (u64)PT_REGS_PARM1(ctx);

    bpf_dbg_printk("=== uprobe AsyncReset id=%d wrap=%llx ===", id, wrap);
    bpf_map_update_elem(&async_reset_args, &id, &wrap, BPF_ANY);

    return 0;
}

SEC("uprobe/node:EmitAsyncInit")
int beyla_emit_async_init(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe EmitAsyncInit id=%d ===", id);

    u64 *wrap_val = bpf_map_lookup_elem(&async_reset_args, &id);
    bpf_dbg_printk("wrap_val = %llx", wrap_val);
    if (wrap_val) {
        u64 wrap = *wrap_val;
        bpf_dbg_printk("wrap = %llx", wrap);

        if (wrap) {
            u64 async_id = 0;
            u64 trigger_async_id = 0;

            bpf_probe_read_user(&async_id, sizeof(u64), ((void *)wrap) + async_wrap_async_id_off);
            bpf_probe_read_user(
                &trigger_async_id, sizeof(u64), ((void *)wrap) + async_wrap_trigger_async_id_off);

            if (async_id) {
                bpf_map_update_elem(&active_nodejs_ids, &id, &async_id, BPF_ANY);
                if (trigger_async_id) {
                    bpf_map_update_elem(&nodejs_parent_map, &async_id, &trigger_async_id, BPF_ANY);
                    bpf_dbg_printk(
                        "async_id = %llx, trigger_async_id = %llx", async_id, trigger_async_id);
                } else {
                    bpf_dbg_printk("No trigger async id");
                }
            } else {
                bpf_dbg_printk("No async id");
            }
        }
    } else {
        bpf_dbg_printk("No wrap value found");
    }

    return 0;
}

#endif // NODE_JS_H
