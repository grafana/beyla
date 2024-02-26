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
#include "map_sizing.h"
#include "bpf_dbg.h"
#include "http_trace.h"
#include "tracing.h"
#include "trace_util.h"
#include "go_traceparent.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Temporary information about a function invocation. It stores the invocation time of a function
// as well as the value of registers at the invocation time. This way we can retrieve them at the
// return uprobes so we can know the values of the function arguments (which are passed as registers
// since Go 1.17).
// This element is created in the function start probe and stored in the ongoing_http_requests hashmaps.
// Then it is retrieved in the return uprobes and used to know the HTTP call duration as well as its
// attributes (method, path, and status code).

typedef struct goroutine_metadata_t {
    u64 parent;
    u64 timestamp;
} goroutine_metadata;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the goroutine
    __type(value, goroutine_metadata);  // value: timestamp of the goroutine creation
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ongoing_goroutines SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, connection_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http_server_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the goroutine
    __type(value, tp_info_t);  // value: traceparent info
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} go_trace_map SEC(".maps");

static __always_inline u64 find_parent_goroutine(void *goroutine_addr) {
    void *r_addr = goroutine_addr;
    int attempts = 0;
    do {
        void *p_inv = bpf_map_lookup_elem(&go_trace_map, &r_addr);
        if (!p_inv) { // not this goroutine running the server request processing
            // Let's find the parent scope
            goroutine_metadata *g_metadata = (goroutine_metadata *)bpf_map_lookup_elem(&ongoing_goroutines, &r_addr);
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

static __always_inline void decode_go_traceparent(unsigned char *buf, unsigned char *trace_id, unsigned char *span_id, unsigned char *flags) {
    unsigned char *t_id = buf + 2 + 1; // strlen(ver) + strlen("-")
    unsigned char *s_id = buf + 2 + 1 + 32 + 1; // strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-")
    unsigned char *f_id = buf + 2 + 1 + 32 + 1 + 16 + 1; // strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-") + strlen(span_id) + strlen("-")

    decode_hex(trace_id, t_id, TRACE_ID_CHAR_LEN);
    decode_hex(span_id, s_id, SPAN_ID_CHAR_LEN);
    decode_hex(flags, f_id, FLAGS_CHAR_LEN);
} 

static __always_inline void tp_from_parent(tp_info_t *tp, tp_info_t *parent) {
    *((u64 *)tp->trace_id) = *((u64 *)parent->trace_id);
    *((u64 *)(tp->trace_id + 8)) = *((u64 *)(parent->trace_id + 8));
    *((u64 *)tp->parent_id) = *((u64 *)parent->span_id);
    tp->flags = parent->flags;
}

static __always_inline void tp_clone(tp_info_t *dest, tp_info_t *src) {
    *((u64 *)dest->trace_id) = *((u64 *)src->trace_id);
    *((u64 *)(dest->trace_id + 8)) = *((u64 *)(src->trace_id + 8));
    *((u64 *)dest->span_id) = *((u64 *)src->span_id);
    *((u64 *)dest->parent_id) = *((u64 *)src->parent_id);
    dest->flags = src->flags;
}

static __always_inline void server_trace_parent(void *goroutine_addr, tp_info_t *tp, void *req_header) {
    // May get overriden when decoding existing traceparent, but otherwise we set sample ON
    tp->flags = 1;
    // Get traceparent from the Request.Header
    void *traceparent_ptr = extract_traceparent_from_req_headers(req_header);
    if (traceparent_ptr != NULL) {
        unsigned char buf[TP_MAX_VAL_LENGTH];
        long res = bpf_probe_read(buf, sizeof(buf), traceparent_ptr);
        if (res < 0) {
            bpf_dbg_printk("can't copy traceparent header");
            urand_bytes(tp->trace_id, TRACE_ID_SIZE_BYTES);
            *((u64 *)tp->parent_id) = 0;
        } else {
            bpf_dbg_printk("Decoding traceparent from headers %s", buf);
            decode_go_traceparent(buf, tp->trace_id, tp->parent_id, &tp->flags);
        }
    } else {
        connection_info_t *info = bpf_map_lookup_elem(&ongoing_http_server_connections, &goroutine_addr);
        u8 found_info = 0;

        if (info) {
            bpf_dbg_printk("Looking up traceparent for connection info");
            tp_info_pid_t *tp_p = trace_info_for_connection(info);
            if (tp_p) {                
                if (correlated_request_with_current(tp_p)) {
                    bpf_dbg_printk("Found traceparent from trace map, another process.");
                    found_info = 1;
                    tp_from_parent(tp, &tp_p->tp);
                }
            }
        }

        if (!found_info) {
            bpf_dbg_printk("No traceparent in headers, generating");
            urand_bytes(tp->trace_id, TRACE_ID_SIZE_BYTES);
            *((u64 *)tp->parent_id) = 0;
        }
    }

    urand_bytes(tp->span_id, SPAN_ID_SIZE_BYTES);
    bpf_map_update_elem(&go_trace_map, &goroutine_addr, tp, BPF_ANY);
}

static __always_inline u8 client_trace_parent(void *goroutine_addr, tp_info_t *tp_i, void *req_header) {
    // Get traceparent from the Request.Header
    u8 found_trace_id = 0;
    
    // May get overriden when decoding existing traceparent or finding a server span, but otherwise we set sample ON
    tp_i->flags = 1;

    if (req_header) {
        void *traceparent_ptr = extract_traceparent_from_req_headers(req_header);
        if (traceparent_ptr != NULL) {
            unsigned char buf[TP_MAX_VAL_LENGTH];
            long res = bpf_probe_read(buf, sizeof(buf), traceparent_ptr);
            if (res < 0) {
                bpf_dbg_printk("can't copy traceparent header");
            } else {
                found_trace_id = 1;
                decode_go_traceparent(buf, tp_i->trace_id, tp_i->span_id, &tp_i->flags);
            }
        }
    }

    if (!found_trace_id) {
        tp_info_t *tp = 0;

        u64 parent_id = find_parent_goroutine(goroutine_addr);

        if (parent_id) {// we found a parent request
            tp = (tp_info_t *)bpf_map_lookup_elem(&go_trace_map, &parent_id);
        }

        if (tp) {
            bpf_dbg_printk("Found parent request trace_parent %llx", tp);
            tp_from_parent(tp_i, tp);
        } else {
            urand_bytes(tp_i->trace_id, TRACE_ID_SIZE_BYTES);    
        }
        
        urand_bytes(tp_i->span_id, SPAN_ID_SIZE_BYTES);
    }

    return found_trace_id;
}


#endif // GO_COMMON_H