#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <pid/maps/map_sizing.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, k_max_concurrent_pids);
    __type(key, u32);
    __type(value, u64); // using 8 bytes, because array elements are 8 bytes aligned anyway
    __uint(pinning, BEYLA_PIN_INTERNAL);
} valid_pids SEC(".maps");
