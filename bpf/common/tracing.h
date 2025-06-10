#pragma once

#include <bpfcore/vmlinux.h>

#include <common/http_types.h>
#include <common/pin_internal.h>
#include <common/trace_util.h>

#include <maps/trace_map.h>
#include <maps/incoming_trace_map.h>
#include <maps/outgoing_trace_map.h>

#define NANOSECONDS_PER_EPOCH (15LL * 1000000000LL) // 15 seconds
#define NANOSECONDS_PER_IMM_EPOCH (100000000LL)     // 100 ms

volatile const u32 disable_black_box_cp;

#define TRACE_TYPE_SERVER 1
#define TRACE_TYPE_CLIENT 2

static __always_inline void make_tp_string(unsigned char *buf, const tp_info_t *tp) {
    // Version
    *buf++ = '0';
    *buf++ = '0';
    *buf++ = '-';

    // TraceID
    encode_hex(buf, tp->trace_id, TRACE_ID_SIZE_BYTES);
    buf += TRACE_ID_CHAR_LEN;
    *buf++ = '-';

    // SpanID
    encode_hex(buf, tp->span_id, SPAN_ID_SIZE_BYTES);
    buf += SPAN_ID_CHAR_LEN;
    *buf++ = '-';

    // Flags
    *buf++ = '0';
    *buf = (tp->flags == 0) ? '0' : '1';
}

static __always_inline void
trace_key_from_conn(trace_map_key_t *key, const connection_info_t *conn, u32 type) {
    key->conn = *conn;
    // handle port forwarding changes made by proxies
    // TODO: d_port is likely the one changed, but if the server is using
    // ports in the ephemeral range this may not work.
    key->conn.d_port = 0;
    key->type = type;
}

static __always_inline tp_info_pid_t *trace_info_for_connection(const connection_info_t *conn,
                                                                u32 type) {
    trace_map_key_t key = {};
    trace_key_from_conn(&key, conn, type);
    return (tp_info_pid_t *)bpf_map_lookup_elem(&trace_map, &key);
}

static __always_inline void
set_trace_info_for_connection(connection_info_t *conn, u32 type, tp_info_pid_t *info) {
    trace_map_key_t key = {};

    // bpf_dbg_printk("setting trace info, type %d", info->req_type);

    // dbg_print_http_connection_info(conn);

    // unsigned char tp_buf[TP_MAX_VAL_LENGTH];
    // make_tp_string(tp_buf, &info->tp);
    // bpf_d_printk("tp: %s", tp_buf);

    trace_key_from_conn(&key, conn, type);
    bpf_map_update_elem(&trace_map, &key, info, BPF_ANY);
}

static __always_inline void delete_trace_info_for_connection(connection_info_t *conn, u32 type) {
    trace_map_key_t key = {};
    trace_key_from_conn(&key, conn, type);
    bpf_map_delete_elem(&trace_map, &key);
}

static __always_inline u64 current_epoch(u64 ts) {
    u64 temp = ts / NANOSECONDS_PER_EPOCH;
    return temp * NANOSECONDS_PER_EPOCH;
}

static __always_inline u64 current_immediate_epoch(u64 ts) {
    u64 temp = ts / NANOSECONDS_PER_IMM_EPOCH;
    return temp * NANOSECONDS_PER_IMM_EPOCH;
}

static __always_inline u8 correlated_requests(tp_info_t *tp, tp_info_pid_t *existing_tp) {
    if (!existing_tp) {
        return 0;
    }

    // We check for correlated requests which are in order, but from different PIDs
    // Same PID means that we had client port reuse (*unless one was client and the other
    // was a server request, i.e. the type check), which might falsely match prior
    // transaction if it happened during the same epoch.
    if (tp->ts >= existing_tp->tp.ts) {
        return current_epoch(tp->ts) == current_epoch(existing_tp->tp.ts);
    }

    return 0;
}

static __always_inline u8 correlated_request_with_current(tp_info_pid_t *existing_tp) {
    if (!existing_tp) {
        return 0;
    }

    //u64 pid_tid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    //u32 pid = pid_from_pid_tgid(pid_tid);

    // We check for correlated requests which are in order, but from different PIDs
    // Same PID means that we had client port reuse, which might falsely match prior
    // transaction if it happened during the same epoch.
    if (ts >= existing_tp->tp.ts) {
        return current_epoch(ts) == current_epoch(existing_tp->tp.ts);
    }

    return 0;
}

static __always_inline void clear_upper_trace_id(tp_info_t *tp) {
    *((u32 *)(&tp->trace_id[0])) = 0;
    *((u16 *)(&tp->trace_id[4])) = 0;
}

// The trace id is 16 bytes, but we can only use 11 bytes in options
static __always_inline void new_trace_id(tp_info_t *tp) {
    urand_bytes(tp->trace_id, TRACE_ID_SIZE_BYTES);
    //clear_upper_trace_id(tp);
}
