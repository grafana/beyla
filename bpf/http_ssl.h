#ifndef HTTP_SSL_H
#define HTTP_SSL_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "http_types.h"
#include "k_tracer.h"
#include "bpf_dbg.h"
#include "pid.h"
#include "sockaddr.h"
#include "tcp_info.h"

// We use this map to track ssl handshake enter/exit, it should be only
// temporary
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // the pid_tid
    __type(value, u64); // the SSL struct pointer
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} active_ssl_handshakes SEC(".maps");

// LRU map, we don't clean-it up at the moment, which holds onto the mapping
// of the SSL pointer and the current connection. It's setup by the tcp_sendmsg uprobe
// when it's sandwitched between ssl_handshake entry/exit.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);                         // the SSL struct pointer
    __type(value, ssl_pid_connection_info_t); // the pointer to the file descriptor matching ssl
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ssl_to_conn SEC(".maps");

// LRU map, we don't clean-it up at the moment, which holds onto the mapping
// of the pid-tid and the current connection. It's setup by tcp_rcv_established
// in case we miss SSL_do_handshake
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);                         // the pid-tid pair
    __type(value, ssl_pid_connection_info_t); // the pointer to the file descriptor matching ssl
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pid_tid_to_conn SEC(".maps");

// LRU map which holds onto the mapping of an ssl pointer to pid-tid,
// we clean-it up when we lookup by ssl. It's setup by SSL_read for cases where frameworks
// process SSL requests on separate thread pools, e.g. Ruby on Rails
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // the ssl pointer
    __type(value, u64); // the pid tid of the thread in ssl read
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ssl_to_pid_tid SEC(".maps");

// Temporary tracking of ssl_read/ssl_read_ex and ssl_write/ssl_write_ex arguments
typedef struct ssl_args {
    u64 ssl;     // SSL struct pointer
    u64 buf;     // pointer to the buffer we read into
    u64 len_ptr; // size_t pointer of the read/written bytes, used only by SSL_read_ex and SSL_write_ex
} ssl_args_t;

// TODO: we should be able to make this into a single map. It's not a big deal because they are really only
// tracking the parameters of SSL_read and SSL_write, so their memory consumption is minimal. If we can be
// 100% certain that SSL_read will never do an SSL_write, then these can be a single map.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __type(key, u64);
    __type(value, ssl_args_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} active_ssl_read_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __type(key, u64);
    __type(value, ssl_args_t);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} active_ssl_write_args SEC(".maps");

static __always_inline void cleanup_ssl_trace_info(http_info_t *info, void *ssl) {
    if (info->type == EVENT_HTTP_REQUEST) {
        ssl_pid_connection_info_t *ssl_info = bpf_map_lookup_elem(&ssl_to_conn, &ssl);

        if (ssl_info) {
            bpf_dbg_printk(
                "Looking to delete server trace for ssl = %llx, info->type = %d", ssl, info->type);
            //dbg_print_http_connection_info(&ssl_info->conn.conn); // commented out since GitHub CI doesn't like this call
            trace_key_t t_key = {0};
            t_key.extra_id = info->extra_id;
            t_key.p_key.ns = info->pid.ns;
            t_key.p_key.pid = info->task_tid;

            delete_server_trace(&t_key);
        }
    }

    bpf_map_delete_elem(&ssl_to_conn, &ssl);
}

static __always_inline void
cleanup_ssl_server_trace(http_info_t *info, void *ssl, void *buf, u32 len) {
    if (info && http_will_complete(info, buf, len)) {
        cleanup_ssl_trace_info(info, ssl);
    }
}

static __always_inline void cleanup_complete_ssl_server_trace(http_info_t *info, void *ssl) {
    if (info && http_info_complete(info)) {
        cleanup_ssl_trace_info(info, ssl);
    }
}

static __always_inline void
finish_possible_delayed_tls_http_request(pid_connection_info_t *pid_conn, void *ssl) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    if (info) {
        cleanup_complete_ssl_server_trace(info, ssl);
        finish_http(info, pid_conn);
    }
}

static __always_inline void cleanup_trace_info_for_delayed_trace(pid_connection_info_t *pid_conn,
                                                                 void *ssl,
                                                                 void *buf,
                                                                 u32 len) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    cleanup_ssl_server_trace(info, ssl, buf, len);
}

static __always_inline void
handle_ssl_buf(void *ctx, u64 id, ssl_args_t *args, int bytes_len, u8 direction) {
    if (args && bytes_len > 0) {
        void *ssl = ((void *)args->ssl);
        u64 ssl_ptr = (u64)ssl;
        bpf_dbg_printk("SSL_buf id=%d ssl=%llx", id, ssl);
        ssl_pid_connection_info_t *conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);

        if (!conn) {
            conn = bpf_map_lookup_elem(&pid_tid_to_conn, &id);

            if (!conn) {
                // We try even harder, we might have an SSL pointer mapped on another
                // thread, since tcp_rcv_established was handled on another thread pool.
                // First we look up a pid_tid by the ssl pointer, which might've been established
                // by a prior SSL_read on another thread, then we look up in the same map.
                // Clean-up here we are done trying if we don't succeed
                u64 *pid_tid_ptr = bpf_map_lookup_elem(&ssl_to_pid_tid, &ssl_ptr);

                if (pid_tid_ptr) {
                    u64 pid_tid = *pid_tid_ptr;

                    conn = bpf_map_lookup_elem(&pid_tid_to_conn, &pid_tid);
                    bpf_dbg_printk(
                        "Separate pool lookup ssl=%llx, pid=%d, conn=%llx", ssl_ptr, pid_tid, conn);
                } else {
                    bpf_dbg_printk("Other thread lookup failed for ssl=%llx", ssl_ptr);
                }
            }

            // If we found a connection setup by tcp_rcv_established, which means
            // we missed a SSL_do_handshake, update our ssl to connection map to be
            // used by the rest of the SSL lifecycle. We shouldn't rely on the SSL_write
            // being on the same thread as the SSL_read.
            if (conn) {
                bpf_map_delete_elem(&pid_tid_to_conn, &id);
                ssl_pid_connection_info_t c;
                bpf_probe_read(&c, sizeof(ssl_pid_connection_info_t), conn);
                bpf_map_update_elem(&ssl_to_conn, &ssl, &c, BPF_ANY);
            }
        }

        bpf_map_delete_elem(&ssl_to_pid_tid, &ssl_ptr);

        if (!conn) {
            // At this point the threading in the language doesn't allow us to properly match the SSL* with
            // the connection info. We send partial event, at least we can find the path, timing and response.
            // even though we won't have peer information.
            ssl_pid_connection_info_t p_c = {};
            bpf_dbg_printk("setting fake connection info ssl=%llx", ssl);
            __builtin_memcpy(&p_c.p_conn.conn.s_addr, &ssl, sizeof(void *));
            p_c.p_conn.conn.d_port = p_c.p_conn.conn.s_port = p_c.orig_dport = 0;
            p_c.p_conn.pid = pid_from_pid_tgid(id);

            bpf_map_update_elem(&ssl_to_conn, &ssl, &p_c, BPF_ANY);
            conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
        }

        if (conn) {
            // bpf_dbg_printk("conn pid %d", conn.pid);
            // dbg_print_http_connection_info(&conn->p_conn.conn);

            // unsigned char buf[48];
            // bpf_probe_read(buf, 48, (void *)args->buf);
            // for (int i=0; i < 48; i++) {
            //     bpf_dbg_printk("%x ", buf[i]);
            // }
            bpf_map_update_elem(&active_ssl_connections, &conn->p_conn, &ssl_ptr, BPF_ANY);

            // We should attempt to clean up the server trace immediately. The cleanup information
            // is keyed of the *ssl, so when it's delayed we might have different *ssl on the same
            // connection.
            cleanup_trace_info_for_delayed_trace(&conn->p_conn, ssl, (void *)args->buf, bytes_len);
            // must be last, doesn't return
            handle_buf_with_connection(ctx,
                                       &conn->p_conn,
                                       (void *)args->buf,
                                       bytes_len,
                                       WITH_SSL,
                                       direction,
                                       conn->orig_dport);
        } else {
            bpf_dbg_printk("No connection info! This is a bug.");
        }
    }
}

// We start by looking when the SSL handshake is established. In between
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

    ssl_pid_connection_info_t *s_conn = bpf_map_lookup_elem(&ssl_to_conn, &s);
    if (s_conn) {
        finish_possible_delayed_tls_http_request(&s_conn->p_conn, s);
    }

    bpf_map_update_elem(&active_ssl_handshakes, &id, &s, BPF_ANY);

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

    ssl_pid_connection_info_t *s_conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
    if (s_conn) {
        finish_possible_delayed_tls_http_request(&s_conn->p_conn, ssl);
    }

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.len_ptr = 0;

    bpf_map_update_elem(&active_ssl_read_args, &id, &args, BPF_ANY);
    bpf_map_update_elem(&ssl_to_pid_tid,
                        &args.ssl,
                        &id,
                        BPF_NOEXIST); // we must not overwrite here, remember the original thread

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

    // must be last in the function, doesn't return
    handle_ssl_buf(ctx, id, args, ret, TCP_RECV);
    return 0;
}

SEC("uprobe/libssl.so:SSL_read_ex")
int BPF_UPROBE(uprobe_ssl_read_ex,
               void *ssl,
               const void *buf,
               int num,
               size_t *readbytes) { //NOLINT(readability-non-const-parameter)
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_read_ex id=%d ssl=%llx ===", id, ssl);

    ssl_pid_connection_info_t *s_conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
    if (s_conn) {
        finish_possible_delayed_tls_http_request(&s_conn->p_conn, ssl);
    }

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.len_ptr = (u64)readbytes;

    bpf_map_update_elem(&active_ssl_read_args, &id, &args, BPF_ANY);
    bpf_map_update_elem(&ssl_to_pid_tid,
                        &args.ssl,
                        &id,
                        BPF_NOEXIST); // we must not overwrite here, remember the original thread

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

    if (ret != 1 || !args || !args->len_ptr) {
        bpf_map_delete_elem(&active_ssl_read_args, &id);
        return 0;
    }

    size_t read_len = 0;
    bpf_probe_read(&read_len, sizeof(read_len), (void *)args->len_ptr);

    bpf_map_delete_elem(&active_ssl_read_args, &id);
    // must be last in the function, doesn't return
    handle_ssl_buf(ctx, id, args, read_len, TCP_RECV);
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

    bpf_map_update_elem(&active_ssl_write_args, &id, &args, BPF_ANY);

    // must be last in the function, doesn't return
    handle_ssl_buf(ctx, id, &args, num, TCP_SEND);
    return 0;
}

SEC("uretprobe/libssl.so:SSL_write")
int BPF_URETPROBE(uretprobe_ssl_write, int ret) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe SSL_write id=%d ===", id);

    bpf_map_delete_elem(&active_ssl_write_args, &id);

    return 0;
}

SEC("uprobe/libssl.so:SSL_write_ex")
int BPF_UPROBE(uprobe_ssl_write_ex, void *ssl, const void *buf, int num, size_t *written) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_write_ex id=%d ssl=%llx ===", id, ssl);

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;

    bpf_map_update_elem(&active_ssl_write_args, &id, &args, BPF_ANY);

    // must be last in the function, doesn't return
    handle_ssl_buf(ctx, id, &args, num, TCP_SEND);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write_ex")
int BPF_URETPROBE(uretprobe_ssl_write_ex, int ret) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe SSL_write_ex id=%d ===", id);

    bpf_map_delete_elem(&active_ssl_write_args, &id);

    return 0;
}

SEC("uprobe/libssl.so:SSL_shutdown")
int BPF_UPROBE(uprobe_ssl_shutdown, void *s) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_shutdown id=%d ssl=%llx ===", id, s);

    ssl_pid_connection_info_t *s_conn = bpf_map_lookup_elem(&ssl_to_conn, &s);
    if (s_conn) {
        finish_possible_delayed_tls_http_request(&s_conn->p_conn, s);
        bpf_map_delete_elem(&active_ssl_connections, &s_conn->p_conn);
    }

    bpf_map_delete_elem(&ssl_to_conn, &s);
    bpf_map_delete_elem(&ssl_to_pid_tid, &s);

    bpf_map_delete_elem(&pid_tid_to_conn, &id);

    return 0;
}

#endif
