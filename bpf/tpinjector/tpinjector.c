#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_endian.h>

#include <common/http_types.h>
#include <common/send_args.h>
#include <common/ssl_helpers.h>
#include <common/tc_common.h>
#include <common/trace_common.h>
#include <common/trace_util.h>
#include <common/tracing.h>

#include <logger/bpf_dbg.h>

#include <maps/msg_buffers.h>
#include <maps/sock_dir.h>

#include <tpinjector/maps/egress_key_mem.h>
#include <tpinjector/maps/extender_jump_table.h>
#include <tpinjector/maps/pid_connection_info_mem.h>

char __license[] SEC("license") = "Dual MIT/GPL";

enum { k_tail_write_msg_traceparent = 0 };

static __always_inline pid_connection_info_t *pid_conn_info_buf() {
    const int zero = 0;
    return bpf_map_lookup_elem(&pid_connection_info_mem, &zero);
}

static __always_inline egress_key_t *egress_key_buf() {
    const int zero = 0;
    return bpf_map_lookup_elem(&egress_key_mem, &zero);
}

// Extracts what we need for connection_info_t from bpf_sock_ops if the
// communication is IPv4
static __always_inline void sk_ops_extract_key_ip4(struct bpf_sock_ops *ops,
                                                   connection_info_t *conn) {
    __builtin_memcpy(conn->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn->s_ip[3] = ops->local_ip4;
    __builtin_memcpy(conn->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn->d_ip[3] = ops->remote_ip4;

    conn->s_port = ops->local_port;
    conn->d_port = bpf_ntohl(ops->remote_port);
}

// Extracts what we need for connection_info_t from bpf_sock_ops if the
// communication is IPv6
// The order of copying the data from bpf_sock_ops matters and must match how
// the struct is laid in vmlinux.h, otherwise the verifier thinks we are modifying
// the context twice.
static __always_inline void sk_ops_extract_key_ip6(struct bpf_sock_ops *ops,
                                                   connection_info_t *conn) {
    conn->d_ip[0] = ops->remote_ip6[0];
    conn->d_ip[1] = ops->remote_ip6[1];
    conn->d_ip[2] = ops->remote_ip6[2];
    conn->d_ip[3] = ops->remote_ip6[3];
    conn->s_ip[0] = ops->local_ip6[0];
    conn->s_ip[1] = ops->local_ip6[1];
    conn->s_ip[2] = ops->local_ip6[2];
    conn->s_ip[3] = ops->local_ip6[3];

    conn->d_port = bpf_ntohl(ops->remote_port);
    conn->s_port = ops->local_port;
}

// Extracts what we need for connection_info_t from sk_msg_md if the
// communication is IPv4
static __always_inline connection_info_t sk_msg_extract_key_ip4(const struct sk_msg_md *msg) {
    connection_info_t conn = {};

    __builtin_memcpy(conn.s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.s_ip[3] = msg->local_ip4;
    __builtin_memcpy(conn.d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn.d_ip[3] = msg->remote_ip4;

    conn.s_port = msg->local_port;
    conn.d_port = bpf_ntohl(msg->remote_port);

    return conn;
}

// Extracts what we need for connection_info_t from sk_msg_md if the
// communication is IPv6
// The order of copying the data from bpf_sock_ops matters and must match how
// the struct is laid in vmlinux.h, otherwise the verifier thinks we are modifying
// the context twice.
static __always_inline connection_info_t sk_msg_extract_key_ip6(struct sk_msg_md *msg) {
    connection_info_t conn = {};

    sk_msg_read_remote_ip6(msg, conn.d_ip);
    sk_msg_read_local_ip6(msg, conn.s_ip);

    conn.d_port = bpf_ntohl(sk_msg_remote_port(msg));
    conn.s_port = sk_msg_local_port(msg);

    return conn;
}

// Helper that writes in the sock map for a sock_ops program
static __always_inline void bpf_sock_ops_establish_cb(struct bpf_sock_ops *skops) {
    connection_info_t conn = {};

    if (skops->family == AF_INET6) {
        sk_ops_extract_key_ip6(skops, &conn);
    } else {
        sk_ops_extract_key_ip4(skops, &conn);
    }

    bpf_printk("SET s_ip[3]: %llx s_port: %d", conn.s_ip[3], conn.s_port);
    bpf_printk("SET d_ip[3]: %llx d_port: %d", conn.d_ip[3], conn.d_port);

    bpf_sock_hash_update(skops, &sock_dir, &conn, BPF_ANY);
}

// Tracks all outgoing sockets (BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
// We don't track incoming, those would be BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB
SEC("sockops")
int beyla_sockmap_tracker(struct bpf_sock_ops *skops) {
    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        bpf_sock_ops_establish_cb(skops);
        break;
    default:
        break;
    }
    return 0;
}

static __always_inline egress_key_t make_key(const connection_info_t *conn) {
    egress_key_t e_key = {
        .d_port = conn->d_port,
        .s_port = conn->s_port,
    };

    sort_egress_key(&e_key);

    return e_key;
}

// This is setup here for Go tracking. Essentially, when the Go userspace
// probes activate for an outgoing HTTP request they setup this
// outgoing_trace_map for us. We then know this is a connection we should
// be injecting the Traceparent in. Another place which sets up this map is
// the kprobe on tcp_sendmsg, however that happens after the sock_msg runs,
// so we have a different detection for that - protocol_detector.
static __always_inline tp_info_pid_t *get_tp_info_pid(const egress_key_t *e_key) {
    return bpf_map_lookup_elem(&outgoing_trace_map, e_key);
}

static __always_inline void set_tp_info_pid(const egress_key_t *e_key, const tp_info_pid_t *tp_p) {
    bpf_map_update_elem(&outgoing_trace_map, e_key, tp_p, BPF_ANY);
}

static __always_inline void clear_tp_info_pid(const egress_key_t *e_key) {
    bpf_map_delete_elem(&outgoing_trace_map, &e_key);
}

static __always_inline u8 is_tracked_go_request(const tp_info_pid_t *tp) {
    return tp != NULL && tp->valid;
}

// This code is copied from the kprobe on tcp_sendmsg and it's called from
// the sock_msg program, which does the packet extension for injecting the
// Traceparent. Since the sock_msg runs before the kprobe on tcp_sendmsg, we
// need to extend the packet before we'll have the opportunity to setup the
// outgoing_trace_map metadata. We can directly perhaps run the same code that
// the kprobe on tcp_sendmsg does, but it's complicated, no tail calls from
// sock_msg programs and inlining will eventually hit us with the instruction
// limit when we eventually add HTTP2/gRPC support.
static __always_inline u8 protocol_detector(struct sk_msg_md *msg,
                                            u64 id,
                                            const connection_info_t *conn) {
    bpf_dbg_printk("=== [protocol detector] %d size %d===", id, msg->size);

    send_args_t s_args = {.size = msg->size};
    __builtin_memcpy(&s_args.p_conn.conn, conn, sizeof(connection_info_t));

    dbg_print_http_connection_info(&s_args.p_conn.conn);
    sort_connection_info(&s_args.p_conn.conn);
    s_args.p_conn.pid = pid_from_pid_tgid(id);

    if (s_args.size == 0 || is_ssl_connection(&s_args.p_conn)) {
        return 0;
    }

    msg_buffer_t msg_buf = {
        .pos = 0,
    };

    bpf_probe_read_kernel(msg_buf.buf, MAX_PROTOCOL_BUF_SIZE, msg->data);

    // We setup any call that looks like HTTP request to be extended.
    // This must match exactly to what the decision will be for
    // the kprobe program on tcp_sendmsg, which sets up the
    // outgoing_trace_map data used by Traffic Control to write the
    // actual 'Traceparent:...' string.

    const egress_key_t e_key = make_key(conn);

    if (bpf_map_update_elem(&msg_buffers, &e_key, &msg_buf, BPF_ANY)) {
        // fail if we can't setup a msg buffer
        return 0;
    }

    if (is_http_request_buf((const unsigned char *)msg_buf.buf)) {
        bpf_dbg_printk("Setting up request to be extended");

        return 1;
    }

    return 0;
}

static __always_inline connection_info_t get_connection_info(struct sk_msg_md *msg) {
    return msg->family == AF_INET6 ? sk_msg_extract_key_ip6(msg) : sk_msg_extract_key_ip4(msg);
}

// this "beauty" ensures we hold pkt in the same register being range
// validated
static __always_inline unsigned char *
check_pkt_access(unsigned char *buf, //NOLINT(readability-non-const-parameter)
                 u32 offset,
                 const unsigned char *end) {
    unsigned char *ret;

    asm goto("r4 = %[buf]\n"
             "r4 += %[offset]\n"
             "if r4 > %[end] goto %l[error]\n"
             "%[ret] = %[buf]"
             : [ret] "=r"(ret)
             : [buf] "r"(buf), [end] "r"(end), [offset] "i"(offset)
             : "r4"
             : error);

    return ret;
error:
    return NULL;
}

static __always_inline void
encode_hex_skb(unsigned char *dst, const unsigned char *src, u32 src_len) {

#pragma clang loop unroll(full)
    for (u32 i = 0, j = 0; i < src_len; i++) {
        unsigned char p = src[i];

        dst[j++] = hex[(p >> 4) & 0xff];
        dst[j++] = hex[p & 0x0f];
    }
}

static __always_inline void
make_tp_string_skb(unsigned char *buf, const tp_info_t *tp, const unsigned char *end) {
    buf = check_pkt_access(buf, EXTEND_SIZE, end);

    if (!buf) {
        return;
    }

    const __attribute__((unused)) unsigned char *tp_string = buf;

    *buf++ = 'T';
    *buf++ = 'r';
    *buf++ = 'a';
    *buf++ = 'c';
    *buf++ = 'e';
    *buf++ = 'p';
    *buf++ = 'a';
    *buf++ = 'r';
    *buf++ = 'e';
    *buf++ = 'n';
    *buf++ = 't';
    *buf++ = ':';
    *buf++ = ' ';

    // Version
    *buf++ = '0';
    *buf++ = '0';
    *buf++ = '-';

    // Trace ID
    encode_hex_skb(buf, tp->trace_id, TRACE_ID_SIZE_BYTES);
    buf += TRACE_ID_CHAR_LEN;

    *buf++ = '-';

    // SpanID
    encode_hex_skb(buf, tp->span_id, SPAN_ID_SIZE_BYTES);
    buf += SPAN_ID_CHAR_LEN;

    *buf++ = '-';

    *buf++ = '0';
    *buf++ = (tp->flags == 0) ? '0' : '1';
    *buf++ = '\r';
    *buf++ = '\n';

    bpf_dbg_printk("beyla_packet_extender: %s", tp_string);
}

static __always_inline bool
extend_and_write_tp(struct sk_msg_md *msg, u32 offset, const tp_info_t *tp) {
    const long err = bpf_msg_push_data(msg, offset, EXTEND_SIZE, 0);

    if (err != 0) {
        bpf_dbg_printk("failed to push data: %d", err);
        return false;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);
    bpf_dbg_printk(
        "offset to split %d, available: %u, size %u", offset, msg->data_end - msg->data, msg->size);

    if (!msg->data) {
        bpf_dbg_printk("null data");
        return false;
    }

    unsigned char *ptr = msg->data + offset;

    if ((void *)ptr + EXTEND_SIZE >= msg->data_end) {
        bpf_dbg_printk("not enough space");
        return false;
    }

    make_tp_string_skb(ptr, tp, msg->data_end);

    return true;
}

static __always_inline bool write_msg_traceparent(struct sk_msg_md *msg, const tp_info_t *tp) {
    unsigned char *data = ctx_msg_data(msg);

    if (!data) {
        return false;
    }

    const u32 newline_pos = find_first_pos_of(data, ctx_msg_data_end(msg), '\n');

    if (newline_pos == INVALID_POS) {
        return false;
    }

    const u32 write_offset = newline_pos + 1;

    return extend_and_write_tp(msg, write_offset, tp);
}

static __always_inline bool
create_trace_info(u64 id, const connection_info_t *conn, tp_info_pid_t *tp_p) {
    bpf_dbg_printk("=== %s ===", __FUNCTION__);

    pid_connection_info_t *p_conn = pid_conn_info_buf();

    if (!p_conn) {
        return false;
    }

    const u32 pid = pid_from_pid_tgid(id);

    p_conn->conn = *conn;
    p_conn->pid = pid;

    tp_p->tp.ts = bpf_ktime_get_ns();
    tp_p->tp.flags = 1;
    tp_p->valid = 1;
    tp_p->written = 0;
    tp_p->pid = pid;
    tp_p->req_type = EVENT_HTTP_CLIENT; //XXX double check

    urand_bytes(tp_p->tp.span_id, SPAN_ID_SIZE_BYTES);

    if (find_trace_for_client_request(p_conn, p_conn->conn.d_port, &tp_p->tp)) {
        bpf_dbg_printk("found existing tp info");
        return true;
    }

    bpf_dbg_printk("generating tp info");

    new_trace_id(&tp_p->tp);
    __builtin_memset(tp_p->tp.parent_id, 0, sizeof(tp_p->tp.parent_id));

    return true;
}

static __always_inline void
write_go_traceparent(struct sk_msg_md *msg, const egress_key_t *e_key, tp_info_pid_t *tp_pid) {
    bpf_dbg_printk("writing go traceparent");

    bpf_msg_pull_data(msg, 0, msg->size, 0);

    tp_pid->written = write_msg_traceparent(msg, &tp_pid->tp);

    if (tp_pid->written) {
        clear_tp_info_pid(e_key);
    } else {
        bpf_dbg_printk("failed to write go traceparent");
    }
}

static __always_inline bool handle_go_request(struct sk_msg_md *msg,
                                              u64 id,
                                              const connection_info_t *conn,
                                              const egress_key_t *e_key,
                                              tp_info_pid_t *tp_pid) {
    if (!is_tracked_go_request(tp_pid)) {
        return false;
    }

    // We have metadata setup by the Go uprobes telling us we should extend
    // this packet
    if (!protocol_detector(msg, id, conn)) {
        bpf_dbg_printk("found TLS or non HTTP go request, ignoring...");
        return false;
    }

    write_go_traceparent(msg, e_key, tp_pid);

    return true;
}

// Sock_msg program which detects packets where it should add space for
// the 'Traceparent' string. It extends the HTTP header and writes the
// Traceparent string.
SEC("sk_msg")
int beyla_packet_extender(struct sk_msg_md *msg) {
    const u64 id = bpf_get_current_pid_tgid();
    const connection_info_t conn = get_connection_info(msg);
    const egress_key_t e_key = make_key(&conn);

    tp_info_pid_t *tp_pid = get_tp_info_pid(&e_key);

    if (handle_go_request(msg, id, &conn, &e_key, tp_pid)) {
        return SK_PASS;
    }

    // Valid PID only works for kprobes since  Go programs don't add their
    // PIDs to the PID map (we instrument the binaries), handled in the
    // previous check
    if (!valid_pid(id)) {
        return SK_PASS;
    }

    bpf_dbg_printk("MSG %llx:%d ->", conn.s_ip[3], conn.s_port);
    bpf_dbg_printk("MSG TO %llx:%d", conn.d_ip[3], conn.d_port);
    bpf_dbg_printk("MSG SIZE: %u", msg->size);

    bpf_msg_pull_data(msg, 0, msg->size, 0);

    // TODO: execute the protocol handlers here with tail calls, don't
    // rely on tcp_sendmsg to do it and record these message buffers.

    // We must run the protocol detector always, the outgoing trace map
    // might be setup for TCP traffic for L4 propagation.
    const u8 tracked = protocol_detector(msg, id, &conn);

    if (!tracked || msg->size <= MIN_HTTP_SIZE) {
        return SK_PASS;
    }

    bpf_dbg_printk("len %d, s_port %d, buf: %s", msg->size, msg->local_port, msg->data);
    bpf_dbg_printk("ptr = %llx, end = %llx", ctx_msg_data(msg), ctx_msg_data_end(msg));
    bpf_dbg_printk("BUF: '%s'", ctx_msg_data(msg));

    // used for the upcoming tailcall
    tp_info_pid_t *tp_p = tp_buf();
    egress_key_t *e_k = egress_key_buf();

    if (!tp_p || !e_k) {
        return SK_PASS;
    }

    if (tp_pid) {
        __builtin_memcpy(tp_p, tp_pid, sizeof(*tp_p));
    } else if (!create_trace_info(id, &conn, tp_p)) {
        bpf_dbg_printk("no tp info found, bailing");
        return SK_PASS;
    }

    *e_k = e_key;

    bpf_tail_call(msg, &extender_jump_table, k_tail_write_msg_traceparent);

    bpf_dbg_printk("tailcall failed");

    return SK_PASS;
}

//k_tail_write_msg_traceparent
SEC("sk_msg")
int beyla_packet_extender_write_msg_tp(struct sk_msg_md *msg) {
    bpf_dbg_printk("== %s ==", __FUNCTION__);

    tp_info_pid_t *tp_p = tp_buf();

    const egress_key_t *e_key = egress_key_buf();

    if (!tp_p || !e_key) {
        bpf_dbg_printk("empty tp_buf or e_key");
        return SK_PASS;
    }

    bpf_msg_pull_data(msg, 0, msg->size, 0);

    tp_p->written = write_msg_traceparent(msg, &tp_p->tp);

    if (tp_p->written) {
        set_tp_info_pid(e_key, tp_p);
    } else {
        bpf_dbg_printk("failed to write traceparent");
    }

    bpf_dbg_printk("BUF = [%s]", msg->data);

    return SK_PASS;
}
