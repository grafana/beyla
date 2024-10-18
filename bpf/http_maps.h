#ifndef HTTP_MAPS_H
#define HTTP_MAPS_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "http_types.h"

// Keeps track of the ongoing http connections we match for request/response
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t);
    __type(value, http_info_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} ongoing_http SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, http_info_t);
    __uint(max_entries, 1024);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} ongoing_http_fallback SEC(".maps");

#endif
