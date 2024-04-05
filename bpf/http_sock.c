#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_dbg.h"
#include "pid.h"
#include "sockaddr.h"
#include "tcp_info.h"
#include "http_sock.h"
#include "http_ssl.h"

char __license[] SEC("license") = "Dual MIT/GPL";

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

// Temporary tracking of tcp_recvmsg arguments
typedef struct recv_args {
    u64 sock_ptr; // linux sock or socket address
    u64 iovec_ptr;
} recv_args_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, recv_args_t);
} active_recv_args SEC(".maps");

typedef struct send_args {
    pid_connection_info_t p_conn;
    u64 size;
} send_args_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64); // pid_tid
    __type(value, send_args_t); // size to be sent
} active_send_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64); // *sock
    __type(value, send_args_t); // size to be sent
} active_send_sock_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, partial_connection_info_t); // key: the connection info without the destination address, but with the tcp sequence
    __type(value, connection_info_t);  // value: traceparent info
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_connection_map SEC(".maps");

// Used by accept to grab the sock details
SEC("kretprobe/sock_alloc")
int BPF_KRETPROBE(kretprobe_sock_alloc, struct socket *sock) {
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
int BPF_KPROBE(kprobe_tcp_rcv_established, struct sock *sk, struct sk_buff *skb) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    pid_connection_info_t info = {};

    if (parse_sock_info(sk, &info.conn)) {
        sort_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);        
        //dbg_print_http_connection_info(&info.conn);

        http_connection_metadata_t meta = {};
        task_pid(&meta.pid);
        meta.type = EVENT_HTTP_REQUEST;
        bpf_map_update_elem(&filtered_connections, &info, &meta, BPF_NOEXIST); // On purpose BPF_NOEXIST, we don't want to overwrite data by accept or connect
        bpf_map_update_elem(&pid_tid_to_conn, &id, &info, BPF_ANY); // to support SSL on missing handshake
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
int BPF_KRETPROBE(kretprobe_sys_accept4, uint fd)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    //bpf_dbg_printk("=== accept 4 ret id=%d ===", id);

    // The file descriptor is the value returned from the accept4 syscall.
    // If we got a negative file descriptor we don't have a connection
    if ((int)fd < 0) {
        goto cleanup;
    }

    sock_args_t *args = bpf_map_lookup_elem(&active_accept_args, &id);
    if (!args) {
        //bpf_dbg_printk("No sock info %d", id);
        goto cleanup;
    }

    bpf_dbg_printk("=== accept 4 ret id=%d, sock=%llx, fd=%d ===", id, args->addr, fd);

    pid_connection_info_t info = {};

    if (parse_accept_socket_info(args, &info.conn)) {
        sort_connection_info(&info.conn);
        //dbg_print_http_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);

        http_connection_metadata_t meta = {};
        task_pid(&meta.pid);
        meta.type = EVENT_HTTP_REQUEST;
        bpf_map_update_elem(&filtered_connections, &info, &meta, BPF_ANY); // On purpose BPF_ANY, we want to overwrite stale
        bpf_map_update_elem(&pid_tid_to_conn, &id, &info, BPF_ANY); // to support SSL on missing handshake
    }

cleanup:
    bpf_map_delete_elem(&active_accept_args, &id);
    return 0;
}

// Used by connect so that we can grab the sock details
SEC("kprobe/tcp_connect")
int BPF_KPROBE(kprobe_tcp_connect, struct sock *sk) {
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

// We tap into sys_connect so we can track properly the processes doing
// HTTP client calls
SEC("kretprobe/sys_connect")
int BPF_KRETPROBE(kretprobe_sys_connect, int fd)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== connect ret id=%d, pid=%d ===", id, pid_from_pid_tgid(id));

    // The file descriptor is the value returned from the connect syscall.
    // If we got a negative file descriptor we don't have a connection, unless we are in progress
    if (fd < 0 && (fd != -EINPROGRESS)) {
        goto cleanup;
    }

    sock_args_t *args = bpf_map_lookup_elem(&active_connect_args, &id);
    if (!args) {
        bpf_dbg_printk("No sock info %d", id);
        goto cleanup;
    }

    pid_connection_info_t info = {};

    if (parse_connect_sock_info(args, &info.conn)) {
        bpf_dbg_printk("=== connect ret id=%d, pid=%d ===", id, pid_from_pid_tgid(id));
        sort_connection_info(&info.conn);
        //dbg_print_http_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);

        http_connection_metadata_t meta = {};
        task_pid(&meta.pid);
        meta.type = EVENT_HTTP_CLIENT;
        bpf_map_update_elem(&filtered_connections, &info, &meta, BPF_ANY); // On purpose BPF_ANY, we want to overwrite stale
        bpf_map_update_elem(&pid_tid_to_conn, &id, &info, BPF_ANY); // to support SSL 
    }

cleanup:
    bpf_map_delete_elem(&active_connect_args, &id);
    return 0;
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
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kprobe tcp_sendmsg=%d sock=%llx size %d===", id, sk, size);

    send_args_t s_args = {
        .size = size
    };

    if (parse_sock_info(sk, &s_args.p_conn.conn)) {
        //dbg_print_http_connection_info(&info.conn); // commented out since GitHub CI doesn't like this call
        sort_connection_info(&s_args.p_conn.conn);
        s_args.p_conn.pid = pid_from_pid_tgid(id);

        if (size > 0) {
            void *iovec_ptr = find_msghdr_buf(msg);
            if (iovec_ptr) {
                u64 sock_p = (u64)sk;
                bpf_map_update_elem(&active_send_args, &id, &s_args, BPF_ANY);
                bpf_map_update_elem(&active_send_sock_args, &sock_p, &s_args, BPF_ANY);
                handle_buf_with_connection(&s_args.p_conn, iovec_ptr, size, NO_SSL, TCP_SEND);
                // if (size < KPROBES_LARGE_RESPONSE_LEN) {
                //     bpf_dbg_printk("Maybe we need to finish the request");
                //     finish_possible_delayed_http_request(&s_args.p_conn);
                // }
            } else {
                bpf_dbg_printk("can't find iovec ptr in msghdr, not tracking sendmsg");
            }
        }

        void *ssl = 0;
        // Checks if it's sandwitched between active SSL handshake, read or write uprobe/uretprobe
        void **s = bpf_map_lookup_elem(&active_ssl_handshakes, &id);
        if (s) {
            ssl = *s;
        } else {
            ssl_args_t *ssl_args = bpf_map_lookup_elem(&active_ssl_read_args, &id);
            if (!ssl_args) {
                ssl_args = bpf_map_lookup_elem(&active_ssl_write_args, &id);
            }
            if (ssl_args) {
                ssl = (void *)ssl_args->ssl;
            }
        }

        if (!ssl) {
            return 0;
        }
        bpf_dbg_printk("=== kprobe SSL tcp_sendmsg=%d sock=%llx ssl=%llx ===", id, sk, ssl);
        bpf_map_update_elem(&ssl_to_conn, &ssl, &s_args.p_conn, BPF_ANY);
    }

    return 0;
}

// This is really a fallback for the kprobe to ensure we send a large request if it was
// delayed. The code under the `if (size < KPROBES_LARGE_RESPONSE_LEN) {` block should do it
// but it's possible that the kernel sends the data in smaller chunks.
SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(kretprobe_tcp_sendmsg, int sent_len) {
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
        if (sent_len < MIN_HTTP_SIZE) { // Sometimes app servers don't send close, but small responses back
            finish_possible_delayed_http_request(&s_args->p_conn);
        }
    }

    return 0;
}

static __always_inline void ensure_sent_event(u64 id, u64 *sock_p) {
    send_args_t *s_args = bpf_map_lookup_elem(&active_send_args, &id);
    if (s_args) {
        bpf_dbg_printk("Checking if we need to finish the request per thread id");
        finish_possible_delayed_http_request(&s_args->p_conn);
    }  // see if we match on another thread, but same sock *
    s_args = bpf_map_lookup_elem(&active_send_sock_args, sock_p);
    if (s_args) {
        bpf_dbg_printk("Checking if we need to finish the request per socket");
        finish_possible_delayed_http_request(&s_args->p_conn);
    }
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe_tcp_close, struct sock *sk, long timeout) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    u64 sock_p = (u64)sk;

    bpf_printk("=== kprobe tcp_close %d sock %llx ===", id, sk);

    ensure_sent_event(id, &sock_p);

    bpf_map_delete_elem(&active_send_args, &id);
    bpf_map_delete_elem(&active_send_sock_args, &sock_p);

    return 0;
}

//int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len)
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(kprobe_tcp_recvmsg, struct sock *sk, struct msghdr *msg, size_t len, int flags, int *addr_len) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== tcp_recvmsg id=%d sock=%llx ===", id, sk);

    // Make sure we don't have stale event from earlier socket connection if they are
    // sent through the same socket. This mainly happens if the server overlays virtual
    // threads in the runtime.
    u64 sock_p = (u64)sk;
    ensure_sent_event(id, &sock_p);

    // Important: We must work here to remember the iovec pointer, since the msghdr structure
    // can get modified in non-reversible way if the incoming packet is large and broken down in parts. 
    recv_args_t args = {
        .sock_ptr = (u64)sk,
        .iovec_ptr = (u64)find_msghdr_buf(msg)
    };

    bpf_map_update_elem(&active_recv_args, &id, &args, BPF_ANY);

    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(kretprobe_tcp_recvmsg, int copied_len) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    recv_args_t *args = bpf_map_lookup_elem(&active_recv_args, &id);

    if (!args || (copied_len <= 0)) {
        goto done;
    }

    bpf_dbg_printk("=== tcp_recvmsg ret id=%d sock=%llx copied_len %d ===", id, args->sock_ptr, copied_len);

    if (!args->iovec_ptr) {
        bpf_dbg_printk("iovec_ptr found in kprobe is NULL, ignoring this tcp_recvmsg");
    }

    pid_connection_info_t info = {};

    if (parse_sock_info((struct sock *)args->sock_ptr, &info.conn)) {
        sort_connection_info(&info.conn);
        //dbg_print_http_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);
        handle_buf_with_connection(&info, (void *)args->iovec_ptr, copied_len, NO_SSL, TCP_RECV);
    }

done:
    bpf_map_delete_elem(&active_recv_args, &id);

    return 0;
}

// Fall-back in case we don't see kretprobe on tcp_recvmsg in high network volume situations
SEC("socket/http_filter")
int socket__http_filter(struct __sk_buff *skb) {
    protocol_info_t tcp = {};
    connection_info_t conn = {};

    if (!read_sk_buff(skb, &tcp, &conn)) {
        return 0;
    }

    // ignore ACK packets
    if (tcp_ack(&tcp)) {
        return 0;
    }

    // ignore empty packets, unless it's TCP FIN or TCP RST
    if (!tcp_close(&tcp) && tcp_empty(&tcp, skb)) {
        return 0;
    }

    // sorting must happen here, before we check or set dups
    sort_connection_info(&conn);
    
    // we don't want to read the whole buffer for every packed that passes our checks, we read only a bit and check if it's truly HTTP request/response.
    unsigned char buf[MIN_HTTP_SIZE] = {0};
    bpf_skb_load_bytes(skb, tcp.hdr_len, (void *)buf, sizeof(buf));
    // technically the read should be reversed, but eBPF verifier complains on read with variable length
    u32 len = skb->len - tcp.hdr_len;
    if (len > MIN_HTTP_SIZE) {
        len = MIN_HTTP_SIZE;
    }

    u8 packet_type = 0;
    if (is_http(buf, len, &packet_type)) { // we must check tcp_close second, a packet can be a close and a response
        http_info_t info = {0};
        info.conn_info = conn;

        if (packet_type == PACKET_TYPE_REQUEST) {
            u32 full_len = skb->len - tcp.hdr_len;
            if (full_len > FULL_BUF_SIZE) {
                full_len = FULL_BUF_SIZE;
            }
            read_skb_bytes(skb, tcp.hdr_len, info.buf, full_len);
            u64 cookie = bpf_get_socket_cookie(skb);
            //bpf_dbg_printk("=== http_filter cookie = %llx, tcp_seq=%d len=%d %s ===", cookie, tcp.seq, len, buf);
            //dbg_print_http_connection_info(&conn);
            set_fallback_http_info(&info, &conn, skb->len - tcp.hdr_len);

            // The code below is looking to see if we have recorded black-box trace info on 
            // another interface. We do this for client calls, where essentially the original 
            // request may go out on one interface, but then get re-routed to another, which is
            // common with some k8s environments.
            //
            // This casting is done here to save allocating memory on a per CPU buffer, since
            // we don't need info anymore, we reuse it's space and it's much bigger than
            // partial_connection_info_t.
            partial_connection_info_t *partial = (partial_connection_info_t *)(&info);
            partial->d_port = conn.d_port;
            partial->s_port = conn.s_port;
            partial->tcp_seq = tcp.seq;
            bpf_memcpy(partial->s_addr, conn.s_addr, sizeof(partial->s_addr));

            tp_info_pid_t *trace_info = trace_info_for_connection(&conn);
            if (trace_info) {
                if (cookie) { // we have an actual socket associated
                    bpf_map_update_elem(&tcp_connection_map, partial, &conn, BPF_ANY);
                }
            } else if (!cookie) { // no actual socket for this skb, relayed to another interface
                connection_info_t *prev_conn = bpf_map_lookup_elem(&tcp_connection_map, partial);

                if (prev_conn) {
                    tp_info_pid_t *trace_info = trace_info_for_connection(prev_conn);
                    if (trace_info) {
                        if (current_immediate_epoch(trace_info->tp.ts) == current_immediate_epoch(bpf_ktime_get_ns())) {
                            //bpf_dbg_printk("Found trace info on another interface, setting it up for this connection");
                            tp_info_pid_t other_info = {0};
                            bpf_memcpy(&other_info, trace_info, sizeof(tp_info_pid_t));
                            bpf_map_update_elem(&trace_map, &conn, &other_info, BPF_ANY);
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
int BPF_KRETPROBE(kretprobe_sys_clone, int tid) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id) || tid < 0) {
        return 0;
    }

    pid_key_t parent = {0};
    task_tid(&parent);

    pid_key_t child = {
        .pid = (u32)tid,
        .ns = parent.ns,
    };

    bpf_dbg_printk("sys_clone_ret %d -> %d", id, tid);
    bpf_map_update_elem(&clone_map, &child, &parent, BPF_ANY);
    
    return 0;
}

SEC("kprobe/sys_exit")
int BPF_KPROBE(kprobe_sys_exit, int status) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    pid_key_t task = {0};
    task_tid(&task);

    bpf_dbg_printk("sys_exit %d, pid=%d, valid_pid(id)=%d", id, pid_from_pid_tgid(id), valid_pid(id));
 
    // handle the case when the thread terminates without closing a socket
    send_args_t *s_args = bpf_map_lookup_elem(&active_send_args, &id);
    if (s_args) {
        bpf_dbg_printk("Checking if we need to finish the request per thread id");
        finish_possible_delayed_http_request(&s_args->p_conn);
    }

    bpf_map_delete_elem(&clone_map, &task);
    bpf_map_delete_elem(&server_traces, &task);
    
    return 0;
}