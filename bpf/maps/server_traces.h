#pragma once

#include <bpfcore/utils.h>

#include <common/connection_info.h>
#include <common/tp_info.h>
#include <common/trace_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, trace_key_t);     // key: pid_tid
    __type(value, tp_info_pid_t); // value: traceparent info
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} server_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_part_t); // key: the ephemeral port + address
    __type(value, tp_info_pid_t);        // value: traceparent info
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} server_traces_aux SEC(".maps");
