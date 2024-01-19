#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_dbg.h"
#include "pid.h"
#include "sockaddr.h"
#include "tcp_info.h"
#include "ringbuf.h"
#include "http_sock.h"
#include "http_ssl.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Temporary tracking of accept arguments
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, sock_args_t);
} active_accept_args SEC(".maps");

// Temporary tracking of connect arguments
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, recv_args_t);
} active_recv_args SEC(".maps");

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
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== kprobe tcp_sendmsg=%d sock=%llx size %d===", id, sk, size);

    pid_connection_info_t info = {};

    if (parse_sock_info(sk, &info.conn)) {
        //dbg_print_http_connection_info(&info); // commented out since GitHub CI doesn't like this call
        sort_connection_info(&info.conn);
        info.pid = pid_from_pid_tgid(id);

        if (size > 0) {
            void *iovec_ptr = find_msghdr_buf(msg);
            if (iovec_ptr) {
                handle_buf_with_connection(&info, iovec_ptr, size, 0);
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
        bpf_map_update_elem(&ssl_to_conn, &ssl, &info, BPF_ANY);
    }

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
    bpf_map_delete_elem(&active_recv_args, &id);

    if (!args || (copied_len <= 0)) {
        return 0;
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
        handle_buf_with_connection(&info, (void *)args->iovec_ptr, copied_len, 0);
    }

    return 0;
}

SEC("kretprobe/sys_clone")
int BPF_KRETPROBE(kretprobe_sys_clone, int tid) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id) || tid < 0) {
        return 0;
    }

    u32 parent = (u32)id;

    bpf_dbg_printk("sys_clone_ret %d -> %d", id, tid);
    bpf_map_update_elem(&clone_map, &tid, &parent, BPF_ANY);
    
    return 0;
}

SEC("kprobe/sys_exit")
int BPF_KPROBE(kprobe_sys_exit, int status) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    u32 tid = (u32)id;

    bpf_dbg_printk("sys_exit %d, pid=%d, valid_pid(id)=%d", tid, pid_from_pid_tgid(id), valid_pid(id));
    bpf_map_delete_elem(&clone_map, &tid);
    
    return 0;
}