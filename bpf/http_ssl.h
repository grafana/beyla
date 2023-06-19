#ifndef HTTP_SSL_H
#define HTTP_SSL_H

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "http_types.h"
#include "http_sock.h"

#define MAX_CONCURRENT_SSL_REQUESTS 10000

// We use this map to track ssl hanshake enter/exit, it should be only
// temporary
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);   // the pid_tid 
    __type(value, u64); // the SSL struct pointer
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} active_ssl_handshakes SEC(".maps");

// LRU map, we don't clean-it up at the moment, which holds onto the mapping
// of the SSL pointer and the current connection. It's setup by the tcp_sendmsg uprobe
// when it's sandwitched between ssl_handshake entry/exit.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // the SSL struct pointer
    __type(value, connection_info_t); // the pointer to the file descriptor matching ssl
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ssl_to_conn SEC(".maps");

// LRU map, we don't clean-it up at the moment, which holds onto the mapping
// of the pid-tid and the current connection. It's setup by the by tcp_rcv_established
// in case we miss SSL_do_handshake
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // the pid-tid pair
    __type(value, connection_info_t); // the pointer to the file descriptor matching ssl
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} pid_tid_to_conn SEC(".maps");

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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, ssl_args_t);
} active_ssl_read_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, ssl_args_t);
} active_ssl_write_args SEC(".maps");

static __always_inline void https_buffer_event(void *buf, int len, connection_info_t *conn) {
    u8 packet_type = 0;
    if (is_http(buf, len, &packet_type)) {
        http_info_t in = {0};
        in.conn_info = *conn;

        http_connection_metadata_t meta = {
            .id = bpf_get_current_pid_tgid(),
            .type = EVENT_HTTP_REQUEST
        };

        bpf_dbg_printk("=== https_filter len=%d pid=%d %s ===", len, pid_from_pid_tgid(meta.id), buf);
        //dbg_print_http_connection_info(conn); // commented out since GitHub CI doesn't like this call

        http_info_t *info = get_or_set_http_info(&in, packet_type);
        if (!info) {
            return;
        }

        if (packet_type == PACKET_TYPE_REQUEST) {
            process_http_request(info, buf);
        } else if (packet_type == PACKET_TYPE_RESPONSE) {
            process_http_response(info, buf, &meta);

            // We sometimes don't see the TCP close in the filter, I wish we didn't have to 
            // do this here, but let the filter handle it.
            if (still_responding(info)) {
                info->end_monotime_ns = bpf_ktime_get_ns();
            }
            finish_http(info);
        }

        // we let the regular socket filter do the rest
    }
}

static __always_inline void handle_ssl_buf(u64 id, ssl_args_t *args, int bytes_len) {
    if (args && bytes_len > 0) {
        void *ssl = ((void *)args->ssl);
        bpf_printk("SSL_buf id=%d ssl=%llx", id, ssl);
        connection_info_t *conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);

        if (!conn) {
            conn = bpf_map_lookup_elem(&pid_tid_to_conn, &id);

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

        if (conn) {
            void *read_buf = (void *)args->buf;
            char buf[FULL_BUF_SIZE] = {0};
            
            u32 len = bytes_len & 0x0fffffff; // keep the verifier happy

            if (len > FULL_BUF_SIZE) {
                len = FULL_BUF_SIZE;
            }

            bpf_probe_read(&buf, len * sizeof(char), read_buf);
            bpf_dbg_printk("buffer from SSL %s", buf);
            https_buffer_event(buf, len, conn);
        } else {
            bpf_dbg_printk("No connection info! This is a bug.");
        }
    }
}

#endif
