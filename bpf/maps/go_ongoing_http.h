#pragma once

#include <bpfcore/utils.h>

#include <common/egress_key.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, egress_key_t);
    __type(value, go_addr_key_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} go_ongoing_http SEC(".maps");
