// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef GO_COMMON_H
#define GO_COMMON_H

#include "utils.h"
#include "bpf_dbg.h"
#include "http_trace.h"
#include "ringbuf.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// TODO: make this user-configurable and modify the value from the userspace when
// loading the maps with the Cilium library
#define MAX_CONCURRENT_REQUESTS 500

// Temporary information about a function invocation. It stores the invocation time of a function
// as well as the value of registers at the invocation time. This way we can retrieve them at the
// return uprobes so we can know the values of the function arguments (which are passed as registers
// since Go 1.17).
// This element is created in the function start probe and stored in the ongoing_http_requests hashmaps.
// Then it is retrieved in the return uprobes and used to know the HTTP call duration as well as its
// attributes (method, path, and status code).
typedef struct func_invocation_t {
    u64 start_monotime_ns;
    struct pt_regs regs; // we store registers on invocation to be able to fetch the arguments at return
} func_invocation;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, func_invocation);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} newproc1 SEC(".maps");

typedef struct goroutine_metadata_t {
    u64 parent;
    u64 timestamp;
} goroutine_metadata;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the goroutine
    __type(value, goroutine_metadata);  // value: timestamp of the goroutine creation
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ongoing_goroutines SEC(".maps");


// Shared structure that keeps track of ongoing server requests, HTTP or gRPC
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, func_invocation);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ongoing_server_requests SEC(".maps");


static __always_inline u64 find_parent_goroutine(void *goroutine_addr) {
    void *r_addr = goroutine_addr;
    int attempts = 0;
    do {
        func_invocation *p_inv = bpf_map_lookup_elem(&ongoing_server_requests, &r_addr);
        if (!p_inv) { // not this goroutine running the server request processing
            // Let's find the parent scope
            goroutine_metadata *g_metadata = bpf_map_lookup_elem(&ongoing_goroutines, &r_addr);
            if (g_metadata) {
                // Lookup now to see if the parent was a request
                r_addr = (void *)g_metadata->parent;
            } else {
                break;
            }
        } else {
            bpf_dbg_printk("Found parent %lx", r_addr);
            return (u64)r_addr;
        }

        attempts++;
    } while (attempts < 3); // Up to 3 levels of goroutine nesting allowed

    return 0;
}

#endif // GO_COMMON_H