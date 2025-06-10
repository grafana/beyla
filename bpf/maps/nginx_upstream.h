#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/fd_info.h>
#include <common/connection_info.h>
#include <common/pin_internal.h>
#include <common/map_sizing.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, fd_info_t);                // the fd information with pid, tid
    __type(value, connection_info_part_t); // the ephemeral connection info
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} nginx_upstream SEC(".maps");
