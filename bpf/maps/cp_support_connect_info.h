#pragma once

#include <bpfcore/utils.h>

#include <common/connection_info.h>
#include <common/cp_support_data.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t); // key: conn_info
    __type(value, cp_support_data_t);   // value: tracekey to lookup in server_traces
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} cp_support_connect_info SEC(".maps");
