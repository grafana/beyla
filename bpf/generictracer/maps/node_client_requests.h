#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

#include <generictracer/types/node_client_request_key.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, node_client_request_key);
    __type(value, u64);        // parent (server) connection fd
    __uint(max_entries, 1000); // 1000 nodejs services, small number, nodejs is single threaded
    __uint(pinning, BEYLA_PIN_INTERNAL);
} node_client_requests SEC(".maps");
