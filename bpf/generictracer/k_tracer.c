#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/pin_internal.h>
#include <common/sockaddr.h>
#include <common/ssl_helpers.h>
#include <common/tcp_info.h>

#include <generictracer/k_tracer_defs.h>
#include <generictracer/ssl_defs.h>
#include <generictracer/k_send_receive.h>
#include <generictracer/k_unix_sock.h>

#include <logger/bpf_dbg.h>

#include <maps/msg_buffers.h>
#include <maps/sk_buffers.h>

#include <pid/pid.h>

// Temporary tracking of accept arguments
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, sock_args_t);
} active_accept_args SEC(".maps");

// Temporary tracking of connect arguments
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, sock_args_t);
} active_connect_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(
        key,
        partial_connection_info_t); // key: the connection info without the destination address, but with the tcp sequence
    __type(value, connection_info_t); // value: traceparent info
    __uint(max_entries, 1024);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} tcp_connection_map SEC(".maps");

// Used by accept to grab the sock details
SEC("kretprobe/sock_alloc")
int BPF_KRETPROBE(beyla_kretprobe_sock_alloc, struct socket *sock) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== sock alloc %llx ===", id);

    u64 addr = (u64)sock;

    sock_args_t args = {};

    args.addr = addr;
    args.accept_time = bpf_ktime_get_ns();

    // The socket->sock is not valid until accept finishes, therefore
    // we don't extract ->sock here, we remember the address of socket
    // and parse in sys_accept
    bpf_map_update_elem(&active_accept_args, &id, &args, BPF_ANY);

    return 0;
}

// We tap into accept and connect to figure out if a request is inbound or
// outbound. However, in some cases servers can optimise the accept path if
// the same request is sent over and over. For that reason, in case we miss the
// initial accept, we establish an active filtered connection here. By default
// sets the type to be server HTTP, in client mode we'll overwrite the
// data in the map, since those cannot be optimised.
SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(beyla_kprobe_tcp_rcv_established, struct sock *sk, struct sk_buff *skb) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== tcp_rcv_established id=%d ===", id);

    ssl_pid_connection_info_t pid_info = {};

    if (parse_sock_info(sk, &pid_info.p_conn.conn)) {
        //u16 orig_dport = info.conn.d_port;
        dbg_print_http_connection_info(&pid_info.p_conn.conn);
        sort_connection_info(&pid_info.p_conn.conn);
        pid_info.p_conn.pid = pid_from_pid_tgid(id);

        // This is a current limitation for port ordering detection for SSL.
        // tcp_rcv_established flip flops the ports and we can't tell if it's client or server call.
        // If the source port for a client call is lower, we'll get this wrong.
        // TODO: Need to fix this.
        pid_info.orig_dport = pid_info.p_conn.conn.s_port,
        bpf_map_update_elem(
            &pid_tid_to_conn,
            &id,
            &pid_info,
            BPF_ANY); // to support SSL on missing handshake, respect the original info if there
    }

    return 0;
}

// We tap into both sys_accept and sys_accept4.
// We don't care about the accept entry arguments, since we get only peer information
// we don't have the full picture for the socket.
//
// Note: A current limitation is that likely we won't capture the first accept request. The
// process may have already reached accept, before the instrumenter has launched.
SEC("kretprobe/sys_accept4")
int BPF_KRETPROBE(beyla_kretprobe_sys_accept4, uint fd) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    //bpf_dbg_printk("=== accept 4 ret id=%d ===", id);

    bpf_dbg_printk("=== accept 4 ret id=%d, fd=%d ===", id, fd);

    // The file descriptor is the value returned from the accept4 syscall.
    // If we got a negative file descriptor we don't have a connection
    if ((int)fd < 0) {
        goto cleanup;
    }

    sock_args_t *args = bpf_map_lookup_elem(&active_accept_args, &id);
    if (!args) {
        bpf_dbg_printk("No accept sock info %d", id);
        goto cleanup;
    }

    ssl_pid_connection_info_t info = {};

    if (parse_accept_socket_info(args, &info.p_conn.conn)) {
        u16 orig_dport = info.p_conn.conn.d_port;
        //dbg_print_http_connection_info(&info.conn);
        sort_connection_info(&info.p_conn.conn);
        info.p_conn.pid = pid_from_pid_tgid(id);
        info.orig_dport = orig_dport;

        bpf_map_update_elem(
            &pid_tid_to_conn, &id, &info, BPF_ANY); // to support SSL on missing handshake
    }

cleanup:
    bpf_map_delete_elem(&active_accept_args, &id);
    return 0;
}

// Used by connect so that we can grab the sock details
SEC("kprobe/tcp_connect")
int BPF_KPROBE(beyla_kprobe_tcp_connect, struct sock *sk) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== tcp connect %llx ===", id);

    u64 addr = (u64)sk;

    sock_args_t args = {};

    args.addr = addr;
    args.accept_time = bpf_ktime_get_ns();

    bpf_map_update_elem(&active_connect_args, &id, &args, BPF_ANY);

    return 0;
}

// This helper sets up a map for tracking server to client calls, when
// the connection between the two is unclear by just tracking the threads.
// With thread pools, often times the connect call happens on the same thread
// as the one serving the server request, and it's later delegated to another
// thread to handle the client request.
static __always_inline void setup_cp_support_conn_info(pid_connection_info_t *p_conn,
                                                       u8 real_client) {
    cp_support_data_t ct = {
        .real_client = real_client,
    };

    task_tid(&ct.t_key.p_key);
    u64 extra_id = extra_runtime_id();
    ct.t_key.extra_id = extra_id;

    // Support connection thread pools
    bpf_map_update_elem(&cp_support_connect_info, p_conn, &ct, BPF_ANY);
}

// We tap into sys_connect so we can track properly the processes doing
// HTTP client calls
SEC("kretprobe/sys_connect")
int BPF_KRETPROBE(beyla_kretprobe_sys_connect, int res) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== connect ret id=%d, pid=%d ===", id, pid_from_pid_tgid(id));

    // The file descriptor is the value returned from the connect syscall.
    // If we got a negative file descriptor we don't have a connection, unless we are in progress
    if (res < 0 && (res != -EINPROGRESS)) {
        goto cleanup;
    }

    sock_args_t *args = bpf_map_lookup_elem(&active_connect_args, &id);
    if (!args) {
        bpf_dbg_printk("No sock info %d", id);
        goto cleanup;
    }

    ssl_pid_connection_info_t info = {};

    if (parse_connect_sock_info(args, &info.p_conn.conn)) {
        bpf_dbg_printk("=== connect ret id=%d, pid=%d ===", id, pid_from_pid_tgid(id));
        u16 orig_dport = info.p_conn.conn.d_port;
        dbg_print_http_connection_info(&info.p_conn.conn);
        sort_connection_info(&info.p_conn.conn);
        info.p_conn.pid = pid_from_pid_tgid(id);
        info.orig_dport = orig_dport;

        bpf_map_update_elem(&pid_tid_to_conn, &id, &info, BPF_ANY); // Support SSL lookup

        setup_cp_support_conn_info(&info.p_conn, true);
    }

cleanup:
    bpf_map_delete_elem(&active_connect_args, &id);
    return 0;
}

static __always_inline void
tcp_send_ssl_check(u64 id, void *ssl, pid_connection_info_t *p_conn, u16 orig_dport) {
    bpf_dbg_printk("=== kprobe SSL tcp_sendmsg=%d ssl=%llx ===", id, ssl);
    ssl_pid_connection_info_t *s_conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
    if (s_conn) {
        finish_possible_delayed_tls_http_request(&s_conn->p_conn, ssl);
    }
    ssl_pid_connection_info_t ssl_conn = {
        .orig_dport = orig_dport,
    };
    __builtin_memcpy(&ssl_conn.p_conn, p_conn, sizeof(pid_connection_info_t));
    bpf_map_update_elem(&ssl_to_conn, &ssl, &ssl_conn, BPF_ANY);
}

// Main HTTP read and write operations are handled with tcp_sendmsg and tcp_recvmsg

// The size argument here will be always the total response size.
// However, the return value of tcp_sendmsg tells us how much it sent. When the
// response is large it will get chunked, so we have to use a kretprobe to
// finish the request event, otherwise we won't get accurate timings.
// The problem is that kretprobes can be skipped, otherwise we could always just
// finish the request on the return of tcp_sendmsg. Therefore for any request less
// than 1MB we just finish the request on the kprobe path.
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(beyla_kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kprobe tcp_sendmsg=%d sock=%llx size %d===", id, sk, size);

    send_args_t s_args = {.size = size};

    if (parse_sock_info(sk, &s_args.p_conn.conn)) {
        u16 orig_dport = s_args.p_conn.conn.d_port;
        dbg_print_http_connection_info(
            &s_args.p_conn.conn); // commented out since GitHub CI doesn't like this call
        // Create the egress key before we sort the connection info.
        const egress_key_t e_key = {
            .d_port = s_args.p_conn.conn.d_port,
            .s_port = s_args.p_conn.conn.s_port,
        };
        sort_connection_info(&s_args.p_conn.conn);
        s_args.p_conn.pid = pid_from_pid_tgid(id);
        s_args.orig_dport = orig_dport;

        connect_ssl_to_connection(id, &s_args.p_conn, TCP_SEND);

        void *ssl = is_ssl_connection(&s_args.p_conn);
        if (size > 0) {
            if (!ssl) {
                u8 *buf = iovec_memory();
                if (buf) {
                    size = read_msghdr_buf(msg, buf, size);
                    // If a sock_msg program is installed, this kprobe will fail to
                    // read anything, because the data is in bvec physical pages. However,
                    // the sock_msg will setup a buffer for us if this is the case. We
                    // look up this buffer and use it instead of what we'd get from
                    // calling read_msghdr_buf.
                    if (!size) {
                        msg_buffer_t *m_buf = bpf_map_lookup_elem(&msg_buffers, &e_key);
                        bpf_dbg_printk("No size, m_buf[%llx]", m_buf);
                        if (m_buf) {
                            buf = m_buf->buf;
                            // The buffer setup for us by a sock_msg program is always the
                            // full buffer, but when we extend a packet to be able to inject
                            // a Traceparent field, it will actually be split in 3 chunks:
                            // [before the injected header],[70 bytes for 'Traceparent...'],[the rest].
                            // We don't want the handle_buf_with_connection logic to run more than
                            // once on the same data, so if we find a buf we send all of it to the
                            // handle_buf_with_connection logic and then mark it as seen by making
                            // m_buf->pos be the size of the buffer.
                            if (!m_buf->pos) {
                                size = sizeof(m_buf->buf);
                                m_buf->pos = size;
                                bpf_dbg_printk("msg_buffer: size %d, buf[%s]", size, buf);
                            } else {
                                size = 0;
                            }
                        }
                    }

                    // We couldn't find a buffer, for now we just mark the arguments as failed
                    // and see if on the kretprobe we'll have a backup buffer setup for us
                    // by the socket filter program.
                    if (!size) {
                        s_args.size = -1;
                        bpf_map_update_elem(&active_send_args, &id, &s_args, BPF_ANY);
                        bpf_dbg_printk("can't find iovec ptr in msghdr, not tracking sendmsg");
                        return 0;
                    }

                    u64 sock_p = (u64)sk;
                    bpf_map_update_elem(&active_send_args, &id, &s_args, BPF_ANY);
                    bpf_map_update_elem(&active_send_sock_args, &sock_p, &s_args, BPF_ANY);
                    make_inactive_sk_buffer(&s_args.p_conn.conn);

                    // Logically last for !ssl.
                    handle_buf_with_connection(
                        ctx, &s_args.p_conn, buf, size, NO_SSL, TCP_SEND, orig_dport);
                }
            } else {
                bpf_dbg_printk("tcp_sendmsg for identified SSL connection, ignoring...");
            }
        }

        if (!ssl) {
            return 0;
        }

        tcp_send_ssl_check(id, ssl, &s_args.p_conn, orig_dport);
        bpf_map_delete_elem(&active_send_args, &id);
    }

    return 0;
}

// This is a backup path kprobe in case tcp_sendmsg doesn't fire, which
// happens on certain kernels if sk_msg is attached.
SEC("kprobe/tcp_rate_check_app_limited")
int BPF_KPROBE(beyla_kprobe_tcp_rate_check_app_limited, struct sock *sk) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kprobe tcp_rate_check_app_limited=%d sock=%llx ===", id, sk);

    send_args_t s_args = {};

    if (parse_sock_info(sk, &s_args.p_conn.conn)) {
        u16 orig_dport = s_args.p_conn.conn.d_port;
        dbg_print_http_connection_info(&s_args.p_conn.conn);
        const egress_key_t e_key = {
            .d_port = s_args.p_conn.conn.d_port,
            .s_port = s_args.p_conn.conn.s_port,
        };

        sort_connection_info(&s_args.p_conn.conn);
        s_args.p_conn.pid = pid_from_pid_tgid(id);
        s_args.orig_dport = orig_dport;

        msg_buffer_t *m_buf = bpf_map_lookup_elem(&msg_buffers, &e_key);
        if (m_buf) {
            u8 *buf = m_buf->buf;
            // The buffer setup for us by a sock_msg program is always the
            // full buffer, but when we extend a packet to be able to inject
            // a Traceparent field, it will actually be split in 3 chunks:
            // [before the injected header],[70 bytes for 'Traceparent...'],[the rest].
            // We don't want the handle_buf_with_connection logic to run more than
            // once on the same data, so if we find a buf we send all of it to the
            // handle_buf_with_connection logic and then mark it as seen by making
            // m_buf->pos be the size of the buffer.
            if (!m_buf->pos) {
                u16 size = sizeof(m_buf->buf);
                m_buf->pos = size;
                s_args.size = size;
                bpf_dbg_printk("msg_buffer: size %d, buf[%s]", size, buf);
                u64 sock_p = (u64)sk;
                bpf_map_update_elem(&active_send_args, &id, &s_args, BPF_ANY);
                bpf_map_update_elem(&active_send_sock_args, &sock_p, &s_args, BPF_ANY);
                // must set that any backup buffer on this connection is invalid
                // to avoid replay
                make_inactive_sk_buffer(&s_args.p_conn.conn);

                // Logically last for !ssl.
                handle_buf_with_connection(
                    ctx, &s_args.p_conn, buf, size, NO_SSL, TCP_SEND, orig_dport);
            }
        }

        connect_ssl_to_connection(id, &s_args.p_conn, TCP_SEND);

        void *ssl = is_ssl_connection(&s_args.p_conn);
        if (ssl) {
            make_inactive_sk_buffer(&s_args.p_conn.conn);
            tcp_send_ssl_check(id, ssl, &s_args.p_conn, orig_dport);
        }
    }

    return 0;
}

// This is really a fallback for the kprobe to ensure we send a large request if it was
// delayed. The code under the `if (size < KPROBES_LARGE_RESPONSE_LEN) {` block should do it
// but it's possible that the kernel sends the data in smaller chunks.
SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(beyla_kretprobe_tcp_sendmsg, int sent_len) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kretprobe tcp_sendmsg=%d sent %d===", id, sent_len);

    send_args_t *s_args = bpf_map_lookup_elem(&active_send_args, &id);
    if (s_args) {
        if (sent_len > 0) {
            update_http_sent_len(&s_args->p_conn, sent_len);
        }
        if (sent_len <
            MIN_HTTP_SIZE) { // Sometimes app servers don't send close, but small responses back
            finish_possible_delayed_http_request(&s_args->p_conn);
        }

        // The send_msg buffer couldn't be read, maybe kernel buffers. We consult
        // the buffers captured by the socket filter
        if (s_args->size == -1) {
            sk_msg_buffer_t *msg_buf = bpf_map_lookup_elem(&sk_buffers, &s_args->p_conn.conn);
            if (msg_buf && buffer_is_active(msg_buf)) {
                bpf_dbg_printk(
                    "found backup sk_buffer: size %d, buf[%s]", msg_buf->size, msg_buf->buf);

                bpf_map_delete_elem(&active_send_args, &id);
                handle_buf_with_connection(ctx,
                                           &s_args->p_conn,
                                           msg_buf->buf,
                                           msg_buf->size,
                                           NO_SSL,
                                           TCP_SEND,
                                           s_args->orig_dport);
            }
        }
        // We don't want to delete the the backup buffer here, since with some
        // proxies the data is directly forwarded to the other side and
        // we need the buffer in recvmsg.
    }

    bpf_map_delete_elem(&active_send_args, &id);
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(beyla_kprobe_tcp_close, struct sock *sk, long timeout) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    u64 sock_p = (u64)sk;

    bpf_dbg_printk("=== kprobe tcp_close %d sock %llx ===", id, sk);

    ensure_sent_event(id, &sock_p);

    pid_connection_info_t info = {};

    if (parse_sock_info(sk, &info.conn)) {
        sort_connection_info(&info.conn);
        //dbg_print_http_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);
        terminate_http_request_if_needed(&info);
        bpf_map_delete_elem(&ongoing_tcp_req, &info);
        delete_backup_sk_buff(&info.conn);
        cleanup_tcp_trace_info_if_needed(&info);
    }

    bpf_map_delete_elem(&active_send_args, &id);
    bpf_map_delete_elem(&active_send_sock_args, &sock_p);

    return 0;
}

static __always_inline void setup_recvmsg(u64 id, struct sock *sk, struct msghdr *msg) {
    // Make sure we don't have stale event from earlier socket connection if they are
    // sent through the same socket. This mainly happens if the server overlays virtual
    // threads in the runtime.
    u64 sock_p = (u64)sk;
    ensure_sent_event(id, &sock_p);
    connect_ssl_to_sock(id, sk, TCP_RECV);

    recv_args_t args = {
        .sock_ptr = (u64)sk,
    };

    get_iovec_ctx((iovec_iter_ctx *)&args.iovec_ctx, msg);

    bpf_map_update_elem(&active_recv_args, &id, &args, BPF_ANY);
}

//int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(beyla_kprobe_tcp_recvmsg,
               struct sock *sk,
               struct msghdr *msg,
               size_t len,
               int flags,
               int *addr_len) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== tcp_recvmsg id=%d sock=%llx ===", id, sk);

    setup_recvmsg(id, sk, msg);

    return 0;
}

// This is a duplicated setup functionality from tcp_recvmsg because when
// the sock_msg filter is installed, the tcp_recvmsg doesn't trigger for
// peek into socket channels. We need to track the peek so we can support
// the context propagation. This probe happens before tcp_recvmsg and wraps it
// so if tcp_recvmsg happens, it will overwrite the data in the args.
SEC("kprobe/sock_recvmsg")
int BPF_KPROBE(beyla_kprobe_sock_recvmsg, struct socket *sock, struct msghdr *msg, int flags) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    struct sock *sk = 0;
    BPF_CORE_READ_INTO(&sk, sock, sk);

    bpf_dbg_printk("+++ sock_recvmsg sock=%llx, socket=%llx", sk, sock);
    if (sk) {
        setup_recvmsg(id, sk, msg);
    }

    return 0;
}

// This is a duplicated setup functionality from tcp_recvmsg because when
// the sock_msg filter is installed, the tcp_recvmsg doesn't trigger for
// peek into socket channels. We need to track the peek so we can support
// the context propagation. When tcp_recvmsg happened, the args would be
// cleaned up by that probe and this kprobe won't do anything.
SEC("kretprobe/sock_recvmsg")
int BPF_KRETPROBE(beyla_kretprobe_sock_recvmsg, int copied_len) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    recv_args_t *args = bpf_map_lookup_elem(&active_recv_args, &id);

    bpf_dbg_printk(
        "=== return sock_recvmsg id=%d args=%llx copied_len %d ===", id, args, copied_len);

    if (!args) {
        return 0;
    }

    pid_connection_info_t info = {};

    void *sock_ptr = (void *)args->sock_ptr;

    if (sock_ptr) {
        if (parse_sock_info((struct sock *)sock_ptr, &info.conn)) {
            sort_connection_info(&info.conn);
            info.pid = pid_from_pid_tgid(id);
            setup_cp_support_conn_info(&info, false);
        }
    }

    bpf_map_delete_elem(&active_recv_args, &id);

    return 0;
}

static __always_inline int return_recvmsg(void *ctx, struct sock *in_sock, u64 id, int copied_len) {
    recv_args_t *args = bpf_map_lookup_elem(&active_recv_args, &id);

    bpf_dbg_printk("=== return recvmsg id=%d args=%llx copied_len %d ===", id, args, copied_len);

    pid_connection_info_t info = {};

    if (!args && !in_sock) {
        goto done;
    }

    void *sock_ptr = in_sock;
    if (!sock_ptr) {
        if (args) {
            sock_ptr = (void *)args->sock_ptr;
        } else {
            goto done;
        }
    }

    if (copied_len <= 0) {
        if (parse_sock_info((struct sock *)sock_ptr, &info.conn)) {
            sort_connection_info(&info.conn);
            info.pid = pid_from_pid_tgid(id);
            setup_cp_support_conn_info(&info, false);
        }
        // Don't clean-up. This is called as backup path for the retprobe from
        // tcp_cleanup_rbuf which can come in with 0 bytes and we'll delete
        // the data for completing the request.
        return 0;
    }

    u8 *buf = 0;
    if (args) {
        iovec_iter_ctx *iov_ctx = (iovec_iter_ctx *)&args->iovec_ctx;

        if (!iov_ctx->iov && !iov_ctx->ubuf) {
            bpf_dbg_printk("iovec_ptr found in kprobe is NULL, ignoring this tcp_recvmsg");

            goto done;
        }

        buf = iovec_memory();
        if (buf) {
            copied_len = read_iovec_ctx(iov_ctx, buf, copied_len);
            if (!copied_len) {
                bpf_dbg_printk("Not copied anything");
            }
        }
    }

    if (parse_sock_info((struct sock *)sock_ptr, &info.conn)) {
        const u16 orig_dport = info.conn.d_port;
        //dbg_print_http_connection_info(&info.conn);
        sort_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);

        void *ssl = is_ssl_connection(&info);

        if (!ssl) {

            bpf_dbg_printk("buf = %llx, copied_len %d", buf, copied_len);

            if (!buf || !copied_len) {
                sk_msg_buffer_t *msg_buf = bpf_map_lookup_elem(&sk_buffers, &info.conn);
                // we don't check for inactive here, we don't need to, once
                // we consume a buffer we delete the backup buffer regardless.
                // When proxies forward the traffic to pipes, the buffer will
                // likely be marked as inactive on the sendmsg side to avoid
                // double sending, but we have no other buffer available other than
                // the backup.
                if (msg_buf) {
                    buf = msg_buf->buf;
                    copied_len = msg_buf->size;
                }
                // must delete the backup buffer to avoid replay
                delete_backup_sk_buff(&info.conn);
            }

            if (buf && copied_len) {
                // must delete the backup buffer to avoid replay
                delete_backup_sk_buff(&info.conn);
                bpf_map_delete_elem(&active_recv_args, &id);
                // doesn't return must be logically last statement
                handle_buf_with_connection(
                    ctx, &info, buf, copied_len, NO_SSL, TCP_RECV, orig_dport);
            }
        } else {
            // must delete the backup buffer to avoid replay
            delete_backup_sk_buff(&info.conn);
            bpf_dbg_printk("tcp_recvmsg for an identified SSL connection, ignoring [%llx]...", ssl);
        }
    }

done:
    bpf_map_delete_elem(&active_recv_args, &id);

    return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(beyla_kprobe_tcp_cleanup_rbuf, struct sock *sk, int copied) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== tcp_cleanup_rbuf id=%d copied_len %d ===", id, copied);

#ifdef BPF_DEBUG
    connection_info_t conn = {};

    if (parse_sock_info(sk, &conn)) {
        sort_connection_info(&conn);
        dbg_print_http_connection_info(&conn);
    }
#endif

    return return_recvmsg(ctx, sk, id, copied);
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(beyla_kretprobe_tcp_recvmsg, int copied_len) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kretprobe_tcp_recvmsg id=%d copied_len %d ===", id, copied_len);

    return return_recvmsg(ctx, 0, id, copied_len);
}

// Fall-back in case we don't see kretprobe on tcp_recvmsg in high network volume situations
SEC("socket/http_filter")
int beyla_socket__http_filter(struct __sk_buff *skb) {
    protocol_info_t tcp = {};
    connection_info_t conn = {};

    if (!read_sk_buff(skb, &tcp, &conn)) {
        return 0;
    }

    // ignore empty packets, unless it's TCP FIN or TCP RST
    if (!tcp_close(&tcp) && tcp_empty(&tcp, skb)) {
        return 0;
    }

    // we don't want to read the whole buffer for every packed that passes our checks, we read only a bit and check if it's truly HTTP request/response.
    unsigned char buf[MIN_HTTP_SIZE] = {0};
    bpf_skb_load_bytes(skb, tcp.hdr_len, (void *)buf, sizeof(buf));
    // technically the read should be reversed, but eBPF verifier complains on read with variable length
    u32 len = skb->len - tcp.hdr_len;
    if (len > MIN_HTTP_SIZE) {
        len = MIN_HTTP_SIZE;
    }

    sort_connection_info(&conn);

    sk_msg_buffer_t *sk_buf = bpf_map_lookup_elem(&sk_buffers, &conn);
    if (!sk_buf) {
        sk_buf = empty_sk_buffer();
    }
    if (sk_buf) {
        read_skb_bytes(skb, tcp.hdr_len, sk_buf->buf, sizeof(sk_buf->buf));
        sk_buf->size = len;
        bpf_map_update_elem(&sk_buffers, &conn, sk_buf, BPF_ANY);
    }

    u8 packet_type = 0;
    if (is_http(
            buf,
            len,
            &packet_type)) { // we must check tcp_close second, a packet can be a close and a response
        // this can be very verbose
        //bpf_d_printk("http buf %s", buf);
        //d_print_http_connection_info(&conn);

        if (packet_type == PACKET_TYPE_REQUEST) {
            u32 full_len = skb->len - tcp.hdr_len;
            if (full_len > FULL_BUF_SIZE) {
                full_len = FULL_BUF_SIZE;
            }
            u64 cookie = bpf_get_socket_cookie(skb);
            //bpf_printk("=== http_filter cookie = %llx, len=%d %s ===", cookie, len, buf);
            //dbg_print_http_connection_info(&conn);

            // The code below is looking to see if we have recorded black-box trace info on
            // another interface. We do this for client calls, where essentially the original
            // request may go out on one interface, but then get re-routed to another, which is
            // common with some k8s environments.
            partial_connection_info_t partial = {
                .d_port = conn.d_port,
                .s_port = conn.s_port,
                .tcp_seq = tcp.seq,
            };
            __builtin_memcpy(partial.s_addr, conn.s_addr, sizeof(partial.s_addr));

            tp_info_pid_t *trace_info = trace_info_for_connection(&conn, TRACE_TYPE_CLIENT);
            if (trace_info) {
                if (cookie) { // we have an actual socket associated
                    bpf_map_update_elem(&tcp_connection_map, &partial, &conn, BPF_ANY);
                }
            } else if (!cookie) { // no actual socket for this skb, relayed to another interface
                connection_info_t *prev_conn = bpf_map_lookup_elem(&tcp_connection_map, &partial);

                if (prev_conn) {
                    tp_info_pid_t *trace_info =
                        trace_info_for_connection(prev_conn, TRACE_TYPE_CLIENT);
                    if (trace_info) {
                        if (current_immediate_epoch(trace_info->tp.ts) ==
                            current_immediate_epoch(bpf_ktime_get_ns())) {
                            //bpf_dbg_printk("Found trace info on another interface, setting it up for this connection");
                            tp_info_pid_t other_info = {0};
                            __builtin_memcpy(&other_info, trace_info, sizeof(tp_info_pid_t));
                            set_trace_info_for_connection(&conn, TRACE_TYPE_CLIENT, &other_info);
                        }
                    }
                }
            }
        }
    }

    return 0;
}

/*
    The tracking of the clones is complicated by the fact that in container environments
    the tid returned by the sys_clone call is the namespaced tid, not the host tid which 
    bpf sees normally. To mitigate this we work exclusively with namespaces. Only the clone_map
    and server_traces are keyed off the namespace:pid.
*/
SEC("kretprobe/sys_clone")
int BPF_KRETPROBE(beyla_kretprobe_sys_clone, int tid) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id) || tid < 0) {
        return 0;
    }

    pid_key_t parent = {0};
    task_tid(&parent);

    pid_key_t child = {
        .tid = (u32)tid,
        .ns = parent.ns,
        .pid = parent.pid,
    };

    bpf_dbg_printk("sys_clone_ret %d -> %d", id, tid);
    bpf_map_update_elem(&clone_map, &child, &parent, BPF_ANY);

    return 0;
}

SEC("kprobe/sys_exit")
int BPF_KPROBE(beyla_kprobe_sys_exit, int status) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    trace_key_t task = {0};
    task_tid(&task.p_key);

    bpf_dbg_printk(
        "sys_exit %d, pid=%d, valid_pid(id)=%d", id, pid_from_pid_tgid(id), valid_pid(id));

    bpf_map_delete_elem(&clone_map, &task.p_key);
    // This won't delete trace ids for traces with extra_id, like NodeJS. But,
    // we expect that it doesn't matter, since NodeJS main thread won't exit.
    bpf_map_delete_elem(&server_traces, &task);

    return 0;
}
