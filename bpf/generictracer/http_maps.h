#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/http_types.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, http_info_t);
    __uint(max_entries, 1024);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} ongoing_http_fallback SEC(".maps");
