#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // the pid_tid
    __type(value, u32); // the last seen ino
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} active_unix_socks SEC(".maps");
