#ifndef NODE_JS_H
#define NODE_JS_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "map_sizing.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // the pid_tid 
    __type(value, u64); // the last active async_id
    __uint(max_entries, 1000); // 1000 nodejs services, small number, nodejs is single threaded
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} active_nodejs_ids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // child async_id
    __type(value, u64); // parent async_id
    __uint(max_entries, MAX_CONCURRENT_REQUESTS); 
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} nodejs_parent_map SEC(".maps");

#endif