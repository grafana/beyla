#ifndef TC_SOCK_H
#define TC_SOCK_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "http_types.h"
#include "tc_common.h"
#include "bpf_dbg.h"
#include "tracing.h"
#include "http_ssl_defs.h"
#include "k_tracer_defs.h"

#define SOCKOPS_MAP_SIZE 65535

// A map of sockets which we track with sock_ops. The sock_msg
// program subscribes to this map and runs for each new socket
// activity
// The map size must be max u16 to avoid accidentally losing
// the socket information
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, SOCKOPS_MAP_SIZE);
    __uint(key_size, sizeof(connection_info_t));
    __uint(value_size, sizeof(uint32_t));
} sock_dir SEC(".maps");

// When we split a packet with the sock_msg program to inject
// the Traceparent field, we need to keep track of what's
// written by the Traffic Control probes.
typedef struct tc_http_ctx {
    u32 offset;  // where inside the original packet we saw '\n`
    u32 seen;    // how many bytes we've seen before the offset
    u32 written; // how many of the Traceparent field we've written
} __attribute__((packed)) tc_http_ctx_t;

// A map that keeps all the HTTP packets we've extended with
// the sock_msg program and that Traffic Control needs to write to.
// The map size must be max u16 to avoid accidentally overwriting
// prior information of a live extended header.
struct tc_http_ctx_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);
    __type(value, struct tc_http_ctx);
    __uint(max_entries, SOCKOPS_MAP_SIZE);
} tc_http_ctx_map SEC(".maps");

// Memory buffer and a map bellow as temporary storage for
// the sock_msg buffer which we use to look for the first '\n'
// in the request header
typedef struct msg_data {
    u8 buf[1024];
} msg_data_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, msg_data_t);
    __uint(max_entries, 1);
} buf_mem SEC(".maps");

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
static __always_inline void sk_msg_extract_key_ip4(struct sk_msg_md *msg, connection_info_t *conn) {
    __builtin_memcpy(conn->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn->s_ip[3] = msg->local_ip4;
    __builtin_memcpy(conn->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    conn->d_ip[3] = msg->remote_ip4;

    conn->s_port = msg->local_port;
    conn->d_port = bpf_ntohl(msg->remote_port);
}

// Extracts what we need for connection_info_t from sk_msg_md if the
// communication is IPv6
// The order of copying the data from bpf_sock_ops matters and must match how
// the struct is laid in vmlinux.h, otherwise the verifier thinks we are modifying
// the context twice.
__attribute__((__unused__)) static __always_inline void
sk_msg_extract_key_ip6(struct sk_msg_md *msg, connection_info_t *conn) {
    sk_msg_read_remote_ip6(msg, conn->d_ip);
    sk_msg_read_local_ip6(msg, conn->s_ip);

    conn->d_port = bpf_ntohl(sk_msg_remote_port(msg));
    conn->s_port = sk_msg_local_port(msg);
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
    u32 op = skops->op;

    switch (op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        bpf_sock_ops_establish_cb(skops);
        break;
    default:
        break;
    }
    return 0;
}

// Just a buffer
static __always_inline msg_data_t *buffer() {
    int zero = 0;
    return (msg_data_t *)bpf_map_lookup_elem(&buf_mem, &zero);
}

// This is setup here for Go tracking. Essentially, when the Go userspace
// probes activate for an outgoing HTTP request they setup this
// outgoing_trace_map for us. We then know this is a connection we should
// be injecting the Traceparent in. Another place which sets up this map is
// the kprobe on tcp_sendmsg, however that happens after the sock_msg runs,
// so we have a different detection for that - protocol_detector.
static __always_inline u8 is_tracked(connection_info_t *conn) {
    egress_key_t e_key = {
        .d_port = conn->d_port,
        .s_port = conn->s_port,
    };

    sort_egress_key(&e_key);

    tp_info_pid_t *tp = bpf_map_lookup_elem(&outgoing_trace_map, &e_key);
    return tp != 0;
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
                                            connection_info_t *conn) {
    bpf_dbg_printk("=== [protocol detector] %d size %d===", id, msg->size);

    egress_key_t e_key = {
        .d_port = conn->d_port,
        .s_port = conn->s_port,
    };

    send_args_t s_args = {.size = msg->size};
    __builtin_memcpy(&s_args.p_conn.conn, conn, sizeof(connection_info_t));

    dbg_print_http_connection_info(&s_args.p_conn.conn);
    sort_connection_info(&s_args.p_conn.conn);
    s_args.p_conn.pid = pid_from_pid_tgid(id);

    void *ssl = is_ssl_connection(id, &s_args.p_conn);
    if (s_args.size > 0) {
        if (!ssl) {
            msg_buffer_t msg_buf = {
                .pos = 0,
            };
            bpf_probe_read_kernel(msg_buf.buf, FULL_BUF_SIZE, msg->data);
            // We setup any call that looks like HTTP request to be extended.
            // This must match exactly to what the decision will be for
            // the kprobe program on tcp_sendmsg, which sets up the
            // outgoing_trace_map data used by Traffic Control to write the
            // actual 'Traceparent:...' string.
            if (is_http_request_buf((const unsigned char *)msg_buf.buf)) {
                bpf_dbg_printk("Setting up request to be extended");
                if (bpf_map_update_elem(&msg_buffers, &e_key, &msg_buf, BPF_ANY)) {
                    // fail if we can't setup a msg buffer
                    return 0;
                }

                return 1;
            }
        }
    }

    return 0;
}

// Sock_msg program which detects packets where it should add space for
// the 'Traceparent' string. It doesn't write the value, only spaces the packet
// for Traffic Control to do the writing.
SEC("sk_msg")
int beyla_packet_extender(struct sk_msg_md *msg) {
    u64 id = bpf_get_current_pid_tgid();
    connection_info_t conn = {};

    if (msg->family == AF_INET6) {
        sk_msg_extract_key_ip6(msg, &conn);
    } else {
        sk_msg_extract_key_ip4(msg, &conn);
    }
    u8 tracked = is_tracked(&conn);

    // We need two types of checks here. Valid PID only works for kprobes since
    // Go programs don't add their PIDs to the PID map (we instrument the
    // binaries). Tracked means that we have metadata setup by the Go uprobes
    // telling us we should extend this packet.
    if (!valid_pid(id) && !tracked) {
        return SK_PASS;
    }

    bpf_dbg_printk("MSG %llx:%d ->", conn.s_ip[3], conn.s_port);
    bpf_dbg_printk("MSG TO %llx:%d", conn.d_ip[3], conn.d_port);

    msg_data_t *msg_data = buffer();
    if (!msg_data) {
        return SK_PASS;
    }
    bpf_msg_pull_data(msg, 0, 1024, 0);

    if (!tracked) {
        // If we didn't have metadata (sock_msg runs before the kprobe),
        // we ensure to mark it for any packet we want to extend.
        tracked = protocol_detector(msg, id, &conn);
    }

    u64 len = (u64)msg->data_end - (u64)msg->data;
    if (tracked && len > MIN_HTTP_SIZE) {
        bpf_probe_read_kernel(msg_data->buf, 1024, msg->data);
        bpf_dbg_printk("len %d, s_port %d, buf: %s", len, msg->local_port, msg_data->buf);

        int newline_pos = find_first_pos_of(msg_data->buf, &msg_data->buf[1023], '\n');

        if (newline_pos >= 0) {
            newline_pos++;
            tc_http_ctx_t ctx = {
                .offset = newline_pos,
                .seen = 0,
                .written = 0,
            };
            u32 port = msg->local_port;

            // We first attempt to register the metadata for TC to work with. If we
            // fail, we shouldn't expand the packet!
            long failed = bpf_map_update_elem(&tc_http_ctx_map, &port, &ctx, BPF_ANY);

            if (!failed) {
                // Push extends the packet with empty space and sets up the
                // metadata for Traffic Control to finish the writing. If we
                // fail (non-zero return value), we delete the metadata.
                if (bpf_msg_push_data(msg, newline_pos, EXTEND_SIZE, 0)) {
                    // We two things to disable this context, we set the written
                    // and seen to their max value to disable the TC code, and then
                    // we also attempt delete. This is to ensure that we still have
                    // disabled the TC code if delete failed.
                    if (bpf_map_delete_elem(&tc_http_ctx_map, &port)) {
                        tc_http_ctx_t *bad_ctx = bpf_map_lookup_elem(&tc_http_ctx_map, &port);
                        if (bad_ctx) {
                            bad_ctx->written = EXTEND_SIZE;
                            bad_ctx->seen = bad_ctx->offset;
                        }
                    }
                    bpf_dbg_printk("offset to split %d", newline_pos);
                }
            }
        }
    }

    return SK_PASS;
}

#endif
