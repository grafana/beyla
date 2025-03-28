#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);          // the pid_tid
    __type(value, u64);        // the last active async_id
    __uint(max_entries, 1000); // 1000 nodejs services, small number, nodejs is single threaded
    __uint(pinning, BEYLA_PIN_INTERNAL);
} active_nodejs_ids SEC(".maps");
