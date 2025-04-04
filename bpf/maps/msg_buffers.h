#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/egress_key.h>
#include <common/msg_buffer.h>
#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, egress_key_t);
    __type(value, msg_buffer_t);
    __uint(max_entries, 1000);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} msg_buffers SEC(".maps");
