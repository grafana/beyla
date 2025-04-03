#pragma once

#include <bpfcore/utils.h>

#include <common/map_sizing.h>

#include <pid/pid.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_key_t);   // key: the child pid
    __type(value, pid_key_t); // value: the parent pid
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} clone_map SEC(".maps");
