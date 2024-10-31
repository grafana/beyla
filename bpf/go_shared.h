#ifndef GO_SHARED_H
#define GO_SHARED_H

#include "utils.h"
#include "http_types.h"

typedef struct go_addr_key {
    u64 pid;  // PID of the process
    u64 addr; // Address of the goroutine
} go_addr_key_t;

typedef struct http_func_invocation {
    u64 start_monotime_ns;
    tp_info_t tp;
} http_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, http_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} ongoing_http_client_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, egress_key_t); // key: pointer to the connection info
    __type(value, go_addr_key_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} ongoing_go_http SEC(".maps");

#endif // GO_SHARED_H