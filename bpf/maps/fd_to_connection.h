#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/fd_key.h>
#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, fd_key); // key: fd
    __type(value, connection_info_t);
    __uint(max_entries, 1024);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} fd_to_connection SEC(".maps");
