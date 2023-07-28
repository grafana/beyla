#include "vmlinux.h"
#include "common.h"
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

// Helps us track process names of processes that exited.
// Only used with system wide instrumentation
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u32);
    __type(value, char[16]);
} dead_pids SEC(".maps");

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

    connection_info_t info = {};

    if (parse_sock_info(sk, &info)) {
        sort_connection_info(&info);
        //dbg_print_http_connection_info(&info);

        http_connection_metadata_t meta = {};
        meta.id = id;
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

    connection_info_t info = {};

    if (parse_accept_socket_info(args, &info)) {
        sort_connection_info(&info);
        //dbg_print_http_connection_info(&info);

        http_connection_metadata_t meta = {};
        meta.id = id;
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

    connection_info_t info = {};

    if (parse_connect_sock_info(args, &info)) {
        bpf_dbg_printk("=== connect ret id=%d, pid=%d ===", id, pid_from_pid_tgid(id));
        sort_connection_info(&info);
        //dbg_print_http_connection_info(&info);

        http_connection_metadata_t meta = {};
        meta.id = id;
        meta.type = EVENT_HTTP_CLIENT;
        bpf_map_update_elem(&filtered_connections, &info, &meta, BPF_ANY); // On purpose BPF_ANY, we want to overwrite stale
    }

cleanup:
    bpf_map_delete_elem(&active_connect_args, &id);
    return 0;
}

SEC("kprobe/sys_exit")
int BPF_KPROBE(kprobe_sys_exit, int status) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    u32 pid = pid_from_pid_tgid(id);

    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_dbg_printk("=== sys exit id=%d [%s]===", id, comm);

    bpf_map_update_elem(&dead_pids, &pid, &comm, BPF_ANY); // On purpose BPF_ANY, we want to overwrite stale

    return 0;
}

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

    // ignore duplicate sequences
    if (tcp_dup(&conn, &tcp)) {
        return 0;
    }

    // we don't want to read the whole buffer for every packed that passes our checks, we read only a bit and check if it's trully HTTP request/response.
    char buf[MIN_HTTP_SIZE] = {0};
    bpf_skb_load_bytes(skb, tcp.hdr_len, (void *)buf, sizeof(buf));
    // technically the read should be reversed, but eBPF verifier complains on read with variable length
    u32 len = skb->len - tcp.hdr_len;
    if (len > MIN_HTTP_SIZE) {
        len = MIN_HTTP_SIZE;
    }

    u8 packet_type = 0;
    if (is_http(buf, len, &packet_type) || tcp_close(&tcp)) { // we must check tcp_close second, a packet can be a close and a response
        http_info_t info = {0};
        info.conn_info = conn;

        http_connection_metadata_t *meta = NULL;
        if (packet_type) {
            u32 full_len = skb->len - tcp.hdr_len;
            if (full_len > FULL_BUF_SIZE) {
                full_len = FULL_BUF_SIZE;
            }
            read_skb_bytes(skb, tcp.hdr_len, info.buf, full_len);
            if (packet_type == PACKET_TYPE_RESPONSE) {
                // if we are filtering by application, ignore the packets not for this connection
                meta = bpf_map_lookup_elem(&filtered_connections, &conn);
                //bpf_dbg_printk("Response meta=%lx", meta);
                if (!meta) {
                    return 0;
                }
            }
        }
        bpf_dbg_printk("=== http_filter len=%d pid=%d %s ===", (skb->len - tcp.hdr_len), (meta != NULL) ? pid_from_pid_tgid(meta->id) : -1, buf);
        //dbg_print_http_connection_info(&conn);

        process_http(&info, &tcp, packet_type, (skb->len - tcp.hdr_len), info.buf, meta);
    }

    return 0;
}

// We start by looking whrn the SSL handshake is established. In between
// the start and the end of the SSL handshake, we'll see at least one tcp_sendmsg
// between the parties. Sandwitching this tcp_sendmsg allows us to grab the sock *
// and match it with our SSL *. The sock * will give us the connection info that is
// used by the generic HTTP filter.
SEC("uprobe/libssl.so:SSL_do_handshake")
int BPF_UPROBE(uprobe_ssl_do_handshake, void *s) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe SSL_do_handshake=%d ssl=%llx===", id, s);

    bpf_map_update_elem(&active_ssl_handshakes, &id, &s, BPF_ANY);

    return 0;
}

// Checks if it's sandwitched between active SSL handshake uprobe/uretprobe
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    void **s = bpf_map_lookup_elem(&active_ssl_handshakes, &id);
    if (!s) {
        return 0;
    }

    void *ssl = *s;

    bpf_dbg_printk("=== kprobe tcp_sendmsg=%d sock=%llx ssl=%llx ===", id, sk, ssl);

    connection_info_t info = {};

    if (parse_sock_info(sk, &info)) {
        sort_connection_info(&info);
        //dbg_print_http_connection_info(&info); // commented out since GitHub CI doesn't like this call

        bpf_map_update_elem(&ssl_to_conn, &ssl, &info, BPF_ANY);
    }

    return 0;
}

SEC("uretprobe/libssl.so:SSL_do_handshake")
int BPF_URETPROBE(uretprobe_ssl_do_handshake, int ret) {
    u64 id = bpf_get_current_pid_tgid();
    
    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe SSL_do_handshake=%d", id);

    bpf_map_delete_elem(&active_ssl_handshakes, &id);

    return 0;
}

// SSL read and read_ex are more less the same, but some frameworks use one or the other.
// SSL_read_ex sets an argument pointer with the number of bytes read, while SSL_read returns
// the number of bytes read.
SEC("uprobe/libssl.so:SSL_read")
int BPF_UPROBE(uprobe_ssl_read, void *ssl, const void *buf, int num) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe SSL_read id=%d ssl=%llx ===", id, ssl);

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.len_ptr = 0;

    bpf_map_update_elem(&active_ssl_read_args, &id, &args, BPF_ANY);
    bpf_map_update_elem(&ssl_to_pid_tid, &args.ssl, &id, BPF_NOEXIST); // we must not overwrite here, remember the original thread

    return 0;
}

SEC("uretprobe/libssl.so:SSL_read")
int BPF_URETPROBE(uretprobe_ssl_read, int ret) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe SSL_read id=%d ===", id);

    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_read_args, &id);
    bpf_map_delete_elem(&active_ssl_read_args, &id);

    handle_ssl_buf(id, args, ret);
    return 0;
}

SEC("uprobe/libssl.so:SSL_read_ex")
int BPF_UPROBE(uprobe_ssl_read_ex, void *ssl, const void *buf, int num, size_t *readbytes) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_read_ex id=%d ===", id);

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.len_ptr = (u64)readbytes;

    bpf_map_update_elem(&active_ssl_read_args, &id, &args, BPF_ANY);
    bpf_map_update_elem(&ssl_to_pid_tid, &args.ssl, &id, BPF_NOEXIST); // we must not overwrite here, remember the original thread
    
    return 0;
}

SEC("uretprobe/libssl.so:SSL_read_ex")
int BPF_URETPROBE(uretprobe_ssl_read_ex, int ret) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe SSL_read_ex id=%d ===", id);

    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_read_args, &id);
    bpf_map_delete_elem(&active_ssl_read_args, &id);

    if (ret != 1 || !args || !args->len_ptr) {
        return 0;
    }

    size_t read_len = 0;
    bpf_probe_read(&read_len, sizeof(read_len), (void *)args->len_ptr);

    handle_ssl_buf(id, args, read_len);
    return 0;
}

// SSL write and write_ex are more less the same, but some frameworks use one or the other.
// SSL_write_ex sets an argument pointer with the number of bytes written, while SSL_write returns
// the number of bytes written.
SEC("uprobe/libssl.so:SSL_write")
int BPF_UPROBE(uprobe_ssl_write, void *ssl, const void *buf, int num) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe SSL_write id=%d ssl=%llx ===", id, ssl);

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.len_ptr = 0;

    bpf_map_update_elem(&active_ssl_write_args, &id, &args, BPF_ANY);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write")
int BPF_URETPROBE(uretprobe_ssl_write, int ret) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe SSL_write id=%d ===", id);

    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_write_args, &id);
    bpf_map_delete_elem(&active_ssl_write_args, &id);

    handle_ssl_buf(id, args, ret);
    return 0;
}

SEC("uprobe/libssl.so:SSL_write_ex")
int BPF_UPROBE(uprobe_ssl_write_ex, void *ssl, const void *buf, int num, size_t *written) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_write_ex id=%d ===", id);

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.len_ptr = (u64)written;

    bpf_map_update_elem(&active_ssl_write_args, &id, &args, BPF_ANY);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write_ex")
int BPF_URETPROBE(uretprobe_ssl_write_ex, int ret) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe SSL_write_ex id=%d ===", id);

    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_write_args, &id);
    bpf_map_delete_elem(&active_ssl_write_args, &id);

    if (ret != 1 || !args || !args->len_ptr) {
        return 0;
    }

    size_t wrote_len = 0;
    bpf_probe_read(&wrote_len, sizeof(wrote_len), (void *)args->len_ptr);

    handle_ssl_buf(id, args, wrote_len);
    return 0;
}

SEC("uprobe/libssl.so:SSL_shutdown")
int BPF_UPROBE(uprobe_ssl_shutdown, void *s) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_shutdown id=%d ssl=%llx ===", id, s);

    bpf_map_delete_elem(&ssl_to_conn, &s);
    bpf_map_delete_elem(&pid_tid_to_conn, &id);

    return 0;
}