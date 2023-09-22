#ifndef HTTP_SSL_H
#define HTTP_SSL_H

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "http_types.h"
#include "http_sock.h"

#define MAX_CONCURRENT_SSL_REQUESTS 10000

// We use this map to track ssl handshake enter/exit, it should be only
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
// of the pid-tid and the current connection. It's setup by tcp_rcv_established
// in case we miss SSL_do_handshake
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // the pid-tid pair
    __type(value, connection_info_t); // the pointer to the file descriptor matching ssl
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
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

static __always_inline void send_trace_buff(void *orig_buf, int orig_len, connection_info_t *info) {
    http_buf_t *trace = bpf_ringbuf_reserve(&events, sizeof(http_buf_t), 0);
    if (trace) {
        trace->conn_info = *info;
        trace->flags |= CONN_INFO_FLAG_TRACE;

        int buf_len = orig_len & (TRACE_BUF_SIZE - 1);
        bpf_probe_read(&trace->buf, buf_len, orig_buf);
        
        if (buf_len < TRACE_BUF_SIZE) {
            trace->buf[buf_len] = '\0';
        }

        /*bpf_dbg_printk("Sending buffer %c%c%c%c%c%c%c%c%c%c, copied_size %d", 
            trace->buf[0], trace->buf[1], trace->buf[2], 
            trace->buf[3], trace->buf[4], trace->buf[5],
            trace->buf[6], trace->buf[7], trace->buf[8],
            trace->buf[9], orig_len);
        */

        bpf_ringbuf_submit(trace, get_flags());
    }
}

static __always_inline void https_buffer_event(void *buf, int len, connection_info_t *conn, void *orig_buf, int orig_len) {
    u8 packet_type = 0;
    if (is_http(buf, len, &packet_type)) {
        http_info_t in = {0};
        in.conn_info = *conn;
        in.ssl = 1;

        http_info_t *info = get_or_set_http_info(&in, packet_type);
        if (!info) {
            return;
        }

        bpf_dbg_printk("=== https_filter len=%d pid=%d still_reading=%d ===", len, pid_from_pid_tgid(bpf_get_current_pid_tgid()), still_reading(info));
        //dbg_print_http_connection_info(conn); // commented out since GitHub CI doesn't like this call

        if (packet_type == PACKET_TYPE_REQUEST && (info->status == 0)) {
            send_trace_buff(orig_buf, orig_len, conn);
            process_http_request(info);
            info->len = len;
            bpf_memcpy(info->buf, buf, FULL_BUF_SIZE);
        } else if (packet_type == PACKET_TYPE_RESPONSE) {
            http_connection_metadata_t *meta = bpf_map_lookup_elem(&filtered_connections, conn);
            http_connection_metadata_t dummy_meta = {
                .id = bpf_get_current_pid_tgid(),
                .type = EVENT_HTTP_REQUEST
            };

            if (!meta) {
                meta = &dummy_meta;
            }

            process_http_response(info, buf, meta);

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
            connection_info_t c = {};
            bpf_dbg_printk("setting fake connection info ssl=%llx", ssl);
            bpf_memcpy(&c.s_addr, &ssl, sizeof(void *));
            c.d_port = c.s_port = 0;

            bpf_map_update_elem(&ssl_to_conn, &ssl, &c, BPF_ANY);
            conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
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
            https_buffer_event(buf, len, conn, read_buf, bytes_len);
        } else {
            bpf_dbg_printk("No connection info! This is a bug.");
        }
    }
}

#endif
