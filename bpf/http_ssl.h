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
    __type(value, connection_info_t); // the pointer to the file descriptor matching ssl
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ssl_to_conn SEC(".maps");

// LRU map, we don't clean-it up at the moment, which holds onto the mapping
// of the pid-tid and the current connection. It's setup by tcp_rcv_established
// in case we miss SSL_do_handshake
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // the pid-tid pair
    __type(value, connection_info_t); // the pointer to the file descriptor matching ssl
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

static __always_inline void handle_ssl_buf(u64 id, ssl_args_t *args, int bytes_len, u8 direction) {
    if (args && bytes_len > 0) {
        void *ssl = ((void *)args->ssl);
        u64 ssl_ptr = (u64)ssl;
        bpf_dbg_printk("SSL_buf id=%d ssl=%llx", id, ssl);
        connection_info_t *conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);

        if (!conn) {
            conn = bpf_map_lookup_elem(&pid_tid_to_conn, &id);

            if (!conn) {
                // We try even harder, we might have an SSL pointer mapped on another
                // thread, since tcp_rcv_established was handled on another thread pool.
                // First we look up a pid_tid by the ssl pointer, which might've been established
                // by a prior SSL_read on another thread, then we look up in the same map.
                // Clean-up here we are done trying if we don't succeed
                void *pid_tid_ptr = bpf_map_lookup_elem(&ssl_to_pid_tid, &ssl_ptr);

                if (pid_tid_ptr) {
                    u64 pid_tid;
                    bpf_probe_read(&pid_tid, sizeof(pid_tid), pid_tid_ptr);

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
                connection_info_t c;
                bpf_probe_read(&c, sizeof(connection_info_t), conn);
                bpf_map_update_elem(&ssl_to_conn, &ssl, &c, BPF_ANY);
            }
        }

        bpf_map_delete_elem(&ssl_to_pid_tid, &ssl_ptr);


        if (!conn) {
            // At this point the threading in the language doesn't allow us to properly match the SSL* with
            // the connection info. We send partial event, at least we can find the path, timing and response.
            // even though we won't have peer information.
            connection_info_t c = {};
            bpf_dbg_printk("setting fake connection info ssl=%llx", ssl);
            bpf_memcpy(&c.s_addr, &ssl, sizeof(void *));
            c.d_port = c.s_port = 0;

            bpf_map_update_elem(&ssl_to_conn, &ssl, &c, BPF_ANY);
            conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
        }

        if (conn) {
            pid_connection_info_t pid_conn = {
                .conn = *conn,
                .pid = pid_from_pid_tgid(id)
            };

            // bpf_dbg_printk("conn pid %d", pid_conn.pid);
            // dbg_print_http_connection_info(&pid_conn.conn);

            // unsigned char buf[48];
            // bpf_probe_read(buf, 48, (void *)args->buf);
            // for (int i=0; i < 48; i++) {
            //     bpf_dbg_printk("%x ", buf[i]);
            // }

            handle_buf_with_connection(&pid_conn, (void *)args->buf, bytes_len, WITH_SSL, direction);
        } else {
            bpf_dbg_printk("No connection info! This is a bug.");
        }
    }
}


#endif
