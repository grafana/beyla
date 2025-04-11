#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/egress_key.h>
#include <common/map_sizing.h>
#include <common/msg_buffer.h>
#include <common/pin_internal.h>

#include <logger/bpf_dbg.h>

typedef struct sk_msg_buffer {
    u8 buf[k_kprobes_http2_buf_size];
    u16 size;
    u8 inactive;
    u8 _pad[1];
} sk_msg_buffer_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, sk_msg_buffer_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} sk_buffers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, sk_msg_buffer_t);
    __uint(max_entries, 1);
} sk_buffer_mem SEC(".maps");

// empty_sk_buffer zeroes and return the unique percpu copy in the map
// this function assumes that a given thread is not trying to use many
// instances at the same time
static __always_inline sk_msg_buffer_t *empty_sk_buffer() {
    int zero = 0;
    sk_msg_buffer_t *value = bpf_map_lookup_elem(&sk_buffer_mem, &zero);
    if (value) {
        __builtin_memset(value, 0, sizeof(sk_msg_buffer_t));
    }
    return value;
}

static __always_inline void delete_backup_sk_buff(connection_info_t *conn) {
    bpf_d_printk("deleting sk_buff on");
    d_print_http_connection_info(conn);
    bpf_map_delete_elem(&sk_buffers, conn);
}

static __always_inline u8 buffer_is_active(sk_msg_buffer_t *msg_buf) {
    bpf_d_printk("sk buffer is inactive %d", msg_buf->inactive);
    return !msg_buf->inactive;
}

static __always_inline void mark_sk_buffer_inactive(sk_msg_buffer_t *msg_buf) {
    bpf_d_printk("marked msg_buf as inactive");
    msg_buf->inactive = 1;
}

static __always_inline void make_inactive_sk_buffer(connection_info_t *conn) {
    sk_msg_buffer_t *msg_buf = bpf_map_lookup_elem(&sk_buffers, conn);
    if (!msg_buf) {
        msg_buf = empty_sk_buffer();
    }
    if (msg_buf) {
        bpf_d_printk("marked buffer as inactive");
        d_print_http_connection_info(conn);
        msg_buf->inactive = 1;
        bpf_map_update_elem(&sk_buffers, conn, msg_buf, BPF_ANY);
    }
}
