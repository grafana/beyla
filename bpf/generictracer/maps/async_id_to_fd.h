#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <generictracer/types/async_id_to_fd_key.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, async_id_to_fd_key);
    __type(value, s32);
    __uint(max_entries, 1000);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} async_id_to_fd SEC(".maps");
