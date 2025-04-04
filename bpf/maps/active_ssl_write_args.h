#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/ssl_args.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __type(key, u64);
    __type(value, ssl_args_t);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} active_ssl_write_args SEC(".maps");
