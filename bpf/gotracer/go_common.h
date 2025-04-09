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

#pragma once

#include <bpfcore/utils.h>

#include <common/common.h>
#include <common/go_addr_key.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/trace_util.h>
#include <common/tracing.h>

#include <gotracer/go_offsets.h>

#include <logger/bpf_dbg.h>

char __license[] SEC("license") = "Dual MIT/GPL";

enum { W3C_KEY_LENGTH = 11, W3C_VAL_LENGTH = 55 };

// Temporary information about a function invocation. It stores the invocation time of a function
// as well as the value of registers at the invocation time. This way we can retrieve them at the
// return uprobes so we can know the values of the function arguments (which are passed as registers
// since Go 1.17).
// This element is created in the function start probe and stored in the ongoing_http_requests hashmaps.
// Then it is retrieved in the return uprobes and used to know the HTTP call duration as well as its
// attributes (method, path, and status code).

typedef struct goroutine_metadata_t {
    go_addr_key_t parent;
    u64 timestamp;
} goroutine_metadata;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t);        // key: pointer to the goroutine
    __type(value, goroutine_metadata); // value: timestamp of the goroutine creation
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} ongoing_goroutines SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, connection_info_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} ongoing_server_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, connection_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_client_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the goroutine
    __type(value, tp_info_t);   // value: traceparent info
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} go_trace_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: goroutine
    __type(value, void *);      // the transport *
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_operate_headers SEC(".maps");

typedef struct grpc_transports {
    connection_info_t conn;
    u8 type;
    u8 pad[3];
    tp_info_t tp;
} grpc_transports_t;

// TODO: use go_addr_key_t as key
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the transport pointer
    __type(value, grpc_transports_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_transports SEC(".maps");

typedef struct sql_func_invocation {
    u64 start_monotime_ns;
    u64 sql_param;
    u64 query_len;
    tp_info_t tp;
    connection_info_t conn;
    u8 _pad[4];
} sql_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, go_addr_key_t); // key: pointer to the request goroutine
    __type(value, sql_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_sql_queries SEC(".maps");

typedef struct grpc_header_field {
    u8 *key_ptr;
    u64 key_len;
    u8 *val_ptr;
    u64 val_len;
    u64 sensitive;
} grpc_header_field_t;

// assumes s2 is all lowercase
static __always_inline int bpf_memicmp(const char *s1, const char *s2, s32 size) {
    for (int i = 0; i < size; i++) {
        if (s1[i] != s2[i] && s1[i] != (s2[i] - 32)) // compare with each uppercase character
        {
            return i + 1;
        }
    }

    return 0;
}

static __always_inline u8 valid_trace(const unsigned char *trace_id) {
    return *((u64 *)trace_id) != 0 || *((u64 *)(trace_id + 8)) != 0;
}

static __always_inline void go_addr_key_from_id(go_addr_key_t *current, void *addr) {
    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 pid = pid_from_pid_tgid(pid_tid);

    current->addr = (u64)addr;
    current->pid = pid;
}

static __always_inline u64 find_parent_goroutine(go_addr_key_t *current) {
    if (!current) {
        return 0;
    }

    u64 r_addr = current->addr;
    go_addr_key_t *parent = current;

    int attempts = 0;
    do {
        tp_info_t *p_inv = bpf_map_lookup_elem(&go_trace_map, parent);
        if (!p_inv) { // not this goroutine running the server request processing
            // Let's find the parent scope
            goroutine_metadata *g_metadata =
                (goroutine_metadata *)bpf_map_lookup_elem(&ongoing_goroutines, parent);
            if (g_metadata) {
                // Lookup now to see if the parent was a request
                r_addr = g_metadata->parent.addr;
                parent = &g_metadata->parent;
            } else {
                break;
            }
        } else {
            bpf_dbg_printk("Found parent %lx", r_addr);
            return r_addr;
        }

        attempts++;
    } while (attempts < 3); // Up to 3 levels of goroutine nesting allowed

    return 0;
}

static __always_inline void decode_go_traceparent(unsigned char *buf,
                                                  unsigned char *trace_id,
                                                  unsigned char *span_id,
                                                  unsigned char *flags) {
    unsigned char *t_id = buf + 2 + 1; // strlen(ver) + strlen("-")
    unsigned char *s_id =
        buf + 2 + 1 + 32 + 1; // strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-")
    unsigned char *f_id =
        buf + 2 + 1 + 32 + 1 + 16 +
        1; // strlen(ver) + strlen("-") + strlen(trace_id) + strlen("-") + strlen(span_id) + strlen("-")

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

static __always_inline void
server_trace_parent(void *goroutine_addr, tp_info_t *tp, tp_info_t *found_tp) {
    // May get overridden when decoding existing traceparent, but otherwise we set sample ON
    tp->flags = 1;
    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);
    if (found_tp) {
        bpf_dbg_printk("Decoded from existing traceparent");
        __builtin_memcpy(tp, found_tp, sizeof(tp_info_t));
    } else {
        connection_info_t *info = bpf_map_lookup_elem(&ongoing_server_connections, &g_key);
        u8 found_info = 0;

        if (info) {
            connection_info_t conn = *info;
            // Must sort here, Go connection info retains the original ordering.
            sort_connection_info(&conn);

            // First we look-up if we have information passed down to us from
            // TCP/IP context propagation.
            tp_info_pid_t *existing_tp = bpf_map_lookup_elem(&incoming_trace_map, &conn);
            if (existing_tp) {
                bpf_dbg_printk("Found incoming (TCP) tp for server request");
                found_info = 1;
                tp_from_parent(tp, &existing_tp->tp);
                bpf_map_delete_elem(&incoming_trace_map, &conn);
            } else {
                // If not, we then look up the information in the black-box context map - same node.
                bpf_dbg_printk("Looking up traceparent for connection info");
                tp_info_pid_t *tp_p = trace_info_for_connection(&conn, TRACE_TYPE_CLIENT);
                if (!disable_black_box_cp && tp_p) {
                    if (correlated_request_with_current(tp_p)) {
                        bpf_dbg_printk("Found traceparent from trace map, another process.");
                        found_info = 1;
                        tp_from_parent(tp, &tp_p->tp);
                    }
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
    bpf_map_update_elem(&go_trace_map, &g_key, tp, BPF_ANY);

    unsigned char tp_buf[TP_MAX_VAL_LENGTH];
    make_tp_string(tp_buf, tp);
    bpf_dbg_printk("tp: %s", tp_buf);
}

static __always_inline u8 client_trace_parent(void *goroutine_addr, tp_info_t *tp_i) {
    u8 found_trace_id = 0;

    // May get overridden when decoding existing traceparent or finding a server span, but otherwise we set sample ON
    tp_i->flags = 1;

    go_addr_key_t g_key = {};
    go_addr_key_from_id(&g_key, goroutine_addr);

    // We first check for Cloud web databases (like snowflake), which wrap HTTP calls with SQL
    // statements.
    if (!found_trace_id) {
        sql_func_invocation_t *invocation = bpf_map_lookup_elem(&ongoing_sql_queries, &g_key);
        if (invocation) {
            tp_from_parent(tp_i, &invocation->tp);
            found_trace_id = 1;
        }
    }

    if (!found_trace_id) {
        tp_info_t *tp = 0;

        u64 parent_id = find_parent_goroutine(&g_key);
        go_addr_key_t p_key = {};
        go_addr_key_from_id(&p_key, (void *)parent_id);

        if (parent_id) { // we found a parent request
            tp = (tp_info_t *)bpf_map_lookup_elem(&go_trace_map, &p_key);
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

static __always_inline void read_ip_and_port(u8 *dst_ip, u16 *dst_port, void *src) {
    s64 addr_len = 0;
    void *addr_ip = 0;
    off_table_t *ot = get_offsets_table();

    bpf_probe_read(dst_port,
                   sizeof(u16),
                   (void *)(src + go_offset_of(ot, (go_offset){.v = _tcp_addr_port_ptr_pos})));
    bpf_probe_read(&addr_ip,
                   sizeof(addr_ip),
                   (void *)(src + go_offset_of(ot, (go_offset){.v = _tcp_addr_ip_ptr_pos})));
    if (addr_ip) {
        bpf_probe_read(
            &addr_len,
            sizeof(addr_len),
            (void *)(src + go_offset_of(ot, (go_offset){.v = _tcp_addr_ip_ptr_pos}) + 8));
        if (addr_len == 4) {
            __builtin_memcpy(dst_ip, ip4ip6_prefix, sizeof(ip4ip6_prefix));
            bpf_probe_read(dst_ip + sizeof(ip4ip6_prefix), 4, addr_ip);
        } else if (addr_len == 16) {
            bpf_probe_read(dst_ip, 16, addr_ip);
        }
    }
}

static __always_inline u8 get_conn_info_from_fd(void *fd_ptr, connection_info_t *info) {
    if (fd_ptr) {
        void *laddr_ptr = 0;
        void *raddr_ptr = 0;
        off_table_t *ot = get_offsets_table();
        u64 fd_laddr_pos = go_offset_of(ot, (go_offset){.v = _fd_laddr_pos});

        bpf_probe_read(
            &laddr_ptr, sizeof(laddr_ptr), (void *)(fd_ptr + fd_laddr_pos + 8)); // find laddr
        bpf_probe_read(
            &raddr_ptr,
            sizeof(raddr_ptr),
            (void *)(fd_ptr + go_offset_of(ot, (go_offset){.v = _fd_raddr_pos}) + 8)); // find raddr

        bpf_dbg_printk("laddr_ptr %llx, laddr %llx, raddr %llx",
                       fd_ptr + fd_laddr_pos + 8,
                       laddr_ptr,
                       raddr_ptr);
        if (laddr_ptr && raddr_ptr) {

            // read local
            read_ip_and_port(info->s_addr, &info->s_port, laddr_ptr);

            // read remote
            read_ip_and_port(info->d_addr, &info->d_port, raddr_ptr);

            //dbg_print_http_connection_info(info);

            // IMPORTANT: Unlike kprobes, where we track the sorted connection info
            // in Go we keep the original connection info order, since we only need it
            // sorted when we make server requests or when we populate the trace_map for
            // black box context propagation.

            return 1;
        }
    }

    return 0;
}

// HTTP black-box context propagation
static __always_inline u8 get_conn_info(void *conn_ptr, connection_info_t *info) {
    if (conn_ptr) {
        void *fd_ptr = 0;
        off_table_t *ot = get_offsets_table();

        bpf_probe_read(
            &fd_ptr,
            sizeof(fd_ptr),
            (void *)(conn_ptr + go_offset_of(ot, (go_offset){.v = _conn_fd_pos}))); // find fd

        bpf_dbg_printk("Found fd ptr %llx", fd_ptr);

        return get_conn_info_from_fd(fd_ptr, info);
    }

    return 0;
}

static __always_inline void *unwrap_tls_conn_info(void *conn_ptr, void *tls_state) {
    if (conn_ptr && tls_state) {
        void *c_ptr = 0;
        bpf_probe_read(&c_ptr, sizeof(c_ptr), conn_ptr); // unwrap conn

        bpf_dbg_printk("unwrapped conn ptr %llx", c_ptr);

        if (c_ptr) {
            return c_ptr + 8;
        }
    }

    return conn_ptr;
}

static __always_inline void process_meta_frame_headers(void *frame, tp_info_t *tp) {
    if (!frame) {
        return;
    }

    off_table_t *ot = get_offsets_table();

    void *fields = 0;
    u64 fields_off = go_offset_of(ot, (go_offset){.v = _meta_headers_frame_fields_ptr_pos});
    bpf_probe_read(&fields, sizeof(fields), (void *)(frame + fields_off));
    u64 fields_len = 0;
    bpf_probe_read(&fields_len, sizeof(fields_len), (void *)(frame + fields_off + 8));
    bpf_dbg_printk("fields ptr %llx, len %d", fields, fields_len);
    if (fields && fields_len > 0) {
        for (u8 i = 0; i < 16; i++) {
            if (i >= fields_len) {
                break;
            }
            void *field_ptr = fields + (i * sizeof(grpc_header_field_t));
            //bpf_dbg_printk("field_ptr %llx", field_ptr);
            grpc_header_field_t field = {};
            bpf_probe_read(&field, sizeof(grpc_header_field_t), field_ptr);
            //bpf_dbg_printk("grpc header %s:%s", field.key_ptr, field.val_ptr);
            //bpf_dbg_printk("grpc sizes %d:%d", field.key_len, field.val_len);
            if (field.key_len == W3C_KEY_LENGTH && field.val_len == W3C_VAL_LENGTH) {
                u8 temp[W3C_VAL_LENGTH];

                bpf_probe_read(&temp, W3C_KEY_LENGTH, field.key_ptr);
                if (!bpf_memicmp((const char *)temp, "traceparent", W3C_KEY_LENGTH)) {
                    //bpf_dbg_printk("found grpc traceparent header");
                    bpf_probe_read(&temp, W3C_VAL_LENGTH, field.val_ptr);
                    decode_go_traceparent(temp, tp->trace_id, tp->parent_id, &tp->flags);
                    break;
                }
            }
        }
    }
}
