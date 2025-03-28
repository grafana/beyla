#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <pid/maps/map_sizing.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, k_max_concurrent_pids);
    __type(key, u32);
    __type(value, u32);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} pid_cache SEC(".maps");
