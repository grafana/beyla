#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/http_types.h>
#include <common/tc_common.h>
#include <common/tracing.h>

#include <generictracer/k_send_receive.h>
#include <generictracer/k_tracer_defs.h>
#include <generictracer/protocol_http.h>
#include <generictracer/protocol_tcp.h>

#include <logger/bpf_dbg.h>

#include <maps/active_unix_socks.h>

static __always_inline struct unix_sock *unix_sock_from_socket(struct socket *sock) {
    struct sock *sk;
    BPF_CORE_READ_INTO(&sk, sock, sk);

    return (struct unix_sock *)sk;
}

static __always_inline struct unix_sock *unix_sock_from_sk(struct sock *sk) {
    return (struct unix_sock *)sk;
}

static __always_inline void
connection_info_for_inode(connection_info_t *conn, u32 inode, u32 peer_inode) {
    // ensure they are sorted
    if (peer_inode > inode) {
        conn->s_ip[0] = peer_inode;
        conn->d_ip[0] = inode;
    } else {
        conn->s_ip[0] = inode;
        conn->d_ip[0] = peer_inode;
    }
}

static __always_inline void
pid_connection_info_for_inode(u64 id, pid_connection_info_t *p_conn, u32 inode, u32 peer_inode) {
    p_conn->pid = pid_from_pid_tgid(id);
    connection_info_for_inode(&p_conn->conn, inode, peer_inode);
}

SEC("kprobe/unix_stream_recvmsg")
int BPF_KPROBE(beyla_kprobe_unix_stream_recvmsg,
               struct socket *sock,
               struct msghdr *msg,
               size_t size,
               int flags) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_printk("=== unix_stream recvmsg %d ===", id);

    struct sock *sk;
    BPF_CORE_READ_INTO(&sk, sock, sk);

    if (!sk) {
        bpf_dbg_printk("can't find sock ptr");
        return 0;
    }

    unsigned long inode_number;
    unsigned long peer_inode_number = 0;
    BPF_CORE_READ_INTO(&inode_number, sock, sk, sk_socket, file, f_inode, i_ino);

    struct unix_sock *usock = unix_sock_from_socket(sock);

    if (usock) {
        BPF_CORE_READ_INTO(&peer_inode_number, usock, peer, sk_socket, file, f_inode, i_ino);
    }
    bpf_dbg_printk("ino %d, peer ino %d", inode_number, peer_inode_number);

    if (peer_inode_number) {
        pid_connection_info_t p_conn = {.conn = {0}};
        pid_connection_info_t partial_p_conn = {.conn = {0}};
        pid_connection_info_for_inode(id, &p_conn, inode_number, peer_inode_number);

        // On the first communication between the unix sockets, the peer ino is 0.
        // We look this up on the receive side and fix up the trace information, so
        // that we can correctly correlate the requests.

        // For the trace information, we look up the peer.
        pid_connection_info_for_inode(id, &partial_p_conn, 0, peer_inode_number);

        tp_info_pid_t *existing_tp =
            trace_info_for_connection(&partial_p_conn.conn, TRACE_TYPE_CLIENT);
        // We found the partial client connection info, delete the old one,
        // and add a new one now with the peer information.
        if (existing_tp) {
            tp_info_pid_t tp = *existing_tp;
            delete_trace_info_for_connection(&partial_p_conn.conn, TRACE_TYPE_CLIENT);
            set_trace_info_for_connection(&p_conn.conn, TRACE_TYPE_CLIENT, &tp);
        }

        // For the ongoing information we look up ourselves
        pid_connection_info_for_inode(id, &partial_p_conn, inode_number, 0);

        // Fix up next the HTTP or TCP request info. We try for TCP info first
        // since most commonly this setup of unix sockets is related to FastCGI.
        tcp_req_t *existing_tcp =
            (tcp_req_t *)bpf_map_lookup_elem(&ongoing_tcp_req, &partial_p_conn);
        if (existing_tcp) {
            tcp_req_t *req = empty_tcp_req();
            if (req) {
                __builtin_memcpy(req, existing_tcp, sizeof(tcp_req_t));
                bpf_map_delete_elem(&ongoing_tcp_req, &partial_p_conn);
                bpf_map_update_elem(&ongoing_tcp_req, &p_conn, req, BPF_ANY);
            }
        } else {
            http_info_t *existing_http =
                (http_info_t *)bpf_map_lookup_elem(&ongoing_http, &partial_p_conn);

            if (existing_http) {
                http_info_t *req = empty_http_info();
                if (req) {
                    __builtin_memcpy(req, existing_http, sizeof(http_info_t));
                    bpf_map_delete_elem(&ongoing_http, &partial_p_conn);
                    bpf_map_update_elem(&ongoing_http, &p_conn, req, BPF_ANY);
                }
            }
        }
    }

    // Make sure we don't have stale event from earlier socket connection if they are
    // sent through the same socket. This mainly happens if the server overlays virtual
    // threads in the runtime.
    u64 sock_p = (u64)sk;
    ensure_sent_event(id, &sock_p);

    recv_args_t args = {
        .sock_ptr = (u64)sk,
    };

    get_iovec_ctx((iovec_iter_ctx *)&args.iovec_ctx, msg);

    bpf_map_update_elem(&active_recv_args, &id, &args, BPF_ANY);

    return 0;
}

static __always_inline int return_unix_recvmsg(void *ctx, u64 id, int copied_len) {
    recv_args_t *args = (recv_args_t *)bpf_map_lookup_elem(&active_recv_args, &id);

    bpf_dbg_printk(
        "=== return unix recvmsg id=%d args=%llx copied_len %d ===", id, args, copied_len);

    if (!args || (copied_len <= 0)) {
        return 0;
    }

    iovec_iter_ctx *iov_ctx = (iovec_iter_ctx *)&args->iovec_ctx;

    if (!iov_ctx->iov && !iov_ctx->ubuf) {
        bpf_dbg_printk("iovec_ptr found in kprobe is NULL, ignoring this tcp_recvmsg");
        bpf_map_delete_elem(&active_recv_args, &id);

        return 0;
    }

    struct sock *sock_ptr = (struct sock *)args->sock_ptr;

    unsigned long inode_number;
    unsigned long peer_inode_number = 0;
    BPF_CORE_READ_INTO(&inode_number, sock_ptr, sk_socket, file, f_inode, i_ino);
    struct unix_sock *usock = unix_sock_from_sk(sock_ptr);

    if (usock) {
        BPF_CORE_READ_INTO(&peer_inode_number, usock, peer, sk_socket, file, f_inode, i_ino);
    }

    bpf_dbg_printk("ino %d, peer ino %d", inode_number, peer_inode_number);

    pid_connection_info_t p_conn = {.conn = {0}};

    pid_connection_info_for_inode(id, &p_conn, inode_number, peer_inode_number);

    bpf_map_delete_elem(&active_recv_args, &id);

    u8 *buf = iovec_memory();
    if (buf) {
        // We may read less than copied_len, iovec iterators are limited
        // to const iterations in our BPF code.
        int read_len = read_iovec_ctx(iov_ctx, buf, copied_len);
        if (read_len) {
            // doesn't return must be logically last statement
            handle_buf_with_connection(ctx, &p_conn, buf, read_len, NO_SSL, TCP_RECV, 0);
        } else {
            bpf_dbg_printk("Not copied anything");
        }
    }

    return 0;
}

SEC("kretprobe/unix_stream_recvmsg")
int BPF_KRETPROBE(beyla_kretprobe_unix_stream_recvmsg, size_t copied) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kretprobe_unix_stream_recvmsg id=%d copied_len %d ===", id, copied);

    return return_unix_recvmsg(ctx, id, copied);
}

SEC("kprobe/unix_stream_sendmsg")
int BPF_KPROBE(beyla_kprobe_unix_stream_sendmsg,
               struct socket *sock,
               struct msghdr *msg,
               size_t size) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_printk("=== unix_stream sendmsg %d ===", id);

    struct sock *sk;
    BPF_CORE_READ_INTO(&sk, sock, sk);

    unsigned long inode_number;
    unsigned long peer_inode_number = 0;
    BPF_CORE_READ_INTO(&inode_number, sock, sk, sk_socket, file, f_inode, i_ino);

    struct unix_sock *usock = unix_sock_from_sk(sk);

    if (usock) {
        BPF_CORE_READ_INTO(&peer_inode_number, usock, peer, sk_socket, file, f_inode, i_ino);
    }
    bpf_dbg_printk("ino %d, peer ino %d", inode_number, peer_inode_number);

    send_args_t s_args = {.size = size, .p_conn = {.conn = {0}}, .sock_ptr = (u64)sk};

    pid_connection_info_for_inode(id, &s_args.p_conn, inode_number, peer_inode_number);

    u8 *buf = iovec_memory();
    if (buf) {
        size = read_msghdr_buf(msg, buf, size);
        if (size) {
            bpf_map_update_elem(&active_send_args, &id, &s_args, BPF_ANY);

            if (sk) {
                u64 sock_p = (u64)sk;
                bpf_map_update_elem(&active_send_sock_args, &sock_p, &s_args, BPF_ANY);
            }

            handle_buf_with_connection(ctx, &s_args.p_conn, buf, size, NO_SSL, TCP_SEND, 0);
        } else {
            bpf_dbg_printk("can't find iovec ptr in msghdr, not tracking sendmsg");
        }
    }

    return 0;
}

SEC("kretprobe/unix_stream_sendmsg")
int BPF_KRETPROBE(beyla_kretprobe_unix_stream_sendmsg, int sent_len) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kretprobe unix_stream sendmsg=%d sent %d===", id, sent_len);

    send_args_t *s_args = (send_args_t *)bpf_map_lookup_elem(&active_send_args, &id);
    if (s_args) {
        // Unix socket calls can be interleaved, so for black-box context propagation,
        // we need to differentiate them. We setup here the last sent active ino,
        // which serves as the extra_runtime id. This is enough to differentiate the
        // various requests, because we communicate this extra id to the receiving side
        // and is able to correlate the incoming request.
        if (s_args->sock_ptr) {
            struct sock *sk = (struct sock *)s_args->sock_ptr;
            unsigned long inode_number;
            BPF_CORE_READ_INTO(&inode_number, sk, sk_socket, file, f_inode, i_ino);

            if (inode_number) {
                bpf_map_update_elem(&active_unix_socks, &id, &inode_number, BPF_ANY);
            }
        }

        if (sent_len > 0) {
            update_http_sent_len(&s_args->p_conn, sent_len);
        }

        // Sometimes app servers don't send close, but small responses back
        if (sent_len < MIN_HTTP_SIZE) {
            finish_possible_delayed_http_request(&s_args->p_conn);
        }
    }

    return 0;
}
