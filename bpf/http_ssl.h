#ifndef HTTP_SSL_H
#define HTTP_SSL_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "http_types.h"
#include "http_sock.h"

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
    __type(key, u64);   // the SSL struct pointer
    __type(value, ssl_pid_connection_info_t); // the pointer to the file descriptor matching ssl
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ssl_to_conn SEC(".maps");

// LRU map, we don't clean-it up at the moment, which holds onto the mapping
// of the pid-tid and the current connection. It's setup by tcp_rcv_established
// in case we miss SSL_do_handshake
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // the pid-tid pair
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
    u64 ssl; // SSL struct pointer
    u64 buf; // pointer to the buffer we read into
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

static __always_inline void cleanup_ssl_server_trace(http_info_t *info, void *ssl) {
    if (info && http_info_complete(info) && (info->type == EVENT_HTTP_REQUEST)) {
        ssl_pid_connection_info_t *ssl_info = bpf_map_lookup_elem(&ssl_to_conn, &ssl);

        if (ssl_info) {
            bpf_dbg_printk("Looking to delete server trace for ssl = %llx, info->type = %d", ssl, info->type);
            //dbg_print_http_connection_info(&ssl_info->conn.conn); // commented out since GitHub CI doesn't like this call
            delete_server_trace_tid(&ssl_info->c_tid);
        }
    }
}

static __always_inline void finish_possible_delayed_tls_http_request(pid_connection_info_t *pid_conn, void *ssl) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    if (info) {        
        cleanup_ssl_server_trace(info, ssl);
        finish_http(info, pid_conn);        
    }
}

static __always_inline void cleanup_trace_info_for_delayed_trace(pid_connection_info_t *pid_conn, void *ssl) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    cleanup_ssl_server_trace(info, ssl);
}

static __always_inline void handle_ssl_buf(u64 id, ssl_args_t *args, int bytes_len, u8 direction) {
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
                    bpf_dbg_printk("Separate pool lookup ssl=%llx, pid=%d, conn=%llx", ssl_ptr, pid_tid, conn);
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
            bpf_memcpy(&p_c.conn.conn.s_addr, &ssl, sizeof(void *));
            p_c.conn.conn.d_port = p_c.conn.conn.s_port = p_c.orig_dport = 0;
            p_c.conn.pid = pid_from_pid_tgid(id);
            task_tid(&p_c.c_tid);

            bpf_map_update_elem(&ssl_to_conn, &ssl, &p_c, BPF_ANY);
            conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
        }

        if (conn) {
            // bpf_dbg_printk("conn pid %d", conn.pid);
            // dbg_print_http_connection_info(&conn.conn);

            // unsigned char buf[48];
            // bpf_probe_read(buf, 48, (void *)args->buf);
            // for (int i=0; i < 48; i++) {
            //     bpf_dbg_printk("%x ", buf[i]);
            // }
            bpf_map_update_elem(&active_ssl_connections, &conn->conn, &ssl_ptr, BPF_ANY);
            handle_buf_with_connection(&conn->conn, (void *)args->buf, bytes_len, WITH_SSL, direction, conn->orig_dport);
            // We should attempt to clean up the server trace immediately. The cleanup information
            // is keyed of the *ssl, so when it's delayed we might have different *ssl on the same
            // connection.
            cleanup_trace_info_for_delayed_trace(&conn->conn, ssl);
        } else {
            bpf_dbg_printk("No connection info! This is a bug.");
        }
    }
}

#endif
