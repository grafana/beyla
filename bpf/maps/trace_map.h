#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>
#include <common/trace_map_key.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, trace_map_key_t); // key: the connection info
    __type(value, tp_info_pid_t); // value: traceparent info
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} trace_map SEC(".maps");
