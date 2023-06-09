#ifndef HTTP_SSL_H
#define HTTP_SSL_H

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "http_types.h"
#include "http_sock.h"

#define MAX_CONCURRENT_SSL_REQUESTS 10000

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);   // the pid_tid 
    __type(value, u64); // the SSL struct pointer
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} active_ssl_handshakes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // the SSL struct pointer
    __type(value, connection_info_t); // the pointer to the file descriptor matching ssl
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ssl_to_conn SEC(".maps");

// Temporary tracking of ssl_read arguments
typedef struct ssl_args {
    u64 ssl; // SSL struct pointer
    u64 buf; // pointer to the buffer we read into
    u64 len_ptr; // size_t pointer of the read/written bytes, used only by SSL_read_ex and SSL_write_ex
} ssl_args_t;

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

        bpf_printk("=== https_filter len=%d pid=%d %s ===", len, pid_from_pid_tgid(meta.id), buf);
        dbg_print_http_connection_info(conn);

        http_info_t *info = get_or_set_http_info(&in, packet_type);
        if (!info) {
            return;
        }

        if (packet_type == PACKET_TYPE_REQUEST) {
            process_http_request(info, buf);
        } else if (packet_type == PACKET_TYPE_RESPONSE) {
            process_http_response(info, buf, &meta);
        }

        // we let the regular socket filter do the rest
    }
}

static __always_inline void handle_ssl_buf(u64 id, ssl_args_t *args, int bytes_len) {
    if (args && bytes_len > 0) {
        void *ssl = ((void *)args->ssl);
        bpf_printk("SSL_buf id=%d ssl=%llx", id, ssl);
        connection_info_t *conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
        if (conn) {
            void *read_buf = (void *)args->buf;
            char buf[FULL_BUF_SIZE] = {0};
            
            u32 len = bytes_len & 0x0fffffff; // keep the verifier happy

            if (len > FULL_BUF_SIZE) {
                len = FULL_BUF_SIZE;
            }

            bpf_probe_read(&buf, len * sizeof(char), read_buf);
            bpf_printk("buffer from SSL %s", buf);
            https_buffer_event(buf, len, conn);
        } else {
            bpf_printk("No connection info");
        }
    }
}

#endif