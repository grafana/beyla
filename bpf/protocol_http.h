#ifndef PROTOCOL_HTTP
#define PROTOCOL_HTTP

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "http_types.h"
#include "ringbuf.h"
#include "pid.h"
#include "runtime.h"
#include "protocol_common.h"

// http_info_t became too big to be declared as a variable in the stack.
// We use a percpu array to keep a reusable copy of it
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, http_info_t);
    __uint(max_entries, 1);
} http_info_mem SEC(".maps");

// Keeps track of the ongoing http connections we match for request/response
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t);
    __type(value, http_info_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ongoing_http SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, http_info_t);
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ongoing_http_fallback SEC(".maps");

// empty_http_info zeroes and return the unique percpu copy in the map
// this function assumes that a given thread is not trying to use many
// instances at the same time
static __always_inline http_info_t* empty_http_info() {
    int zero = 0;
    http_info_t *value = bpf_map_lookup_elem(&http_info_mem, &zero);
    if (value) {
        bpf_memset(value, 0, sizeof(http_info_t));
    }
    return value;
}

static __always_inline u8 is_http(unsigned char *p, u32 len, u8 *packet_type) {
    if (len < MIN_HTTP_SIZE) {
        return 0;
    }
    //HTTP/1.x
    if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P') && (p[4] == '/') && (p[5] == '1') && (p[6] == '.')) {
       *packet_type = PACKET_TYPE_RESPONSE;
       return 1;
    } else if (
        ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T') && (p[3] == ' ') && (p[4] == '/')) ||                                                      // GET
        ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T') && (p[4] == ' ') && (p[5] == '/')) ||                                     // POST
        ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T') && (p[3] == ' ') && (p[4] == '/')) ||                                                      // PUT
        ((p[0] == 'P') && (p[1] == 'A') && (p[2] == 'T') && (p[3] == 'C') && (p[4] == 'H') && (p[5] == ' ') && (p[6] == '/')) ||                    // PATCH
        ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E') && (p[6] == ' ') && (p[7] == '/')) ||   // DELETE
        ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D') && (p[4] == ' ') && (p[5] == '/')) ||                                     // HEAD
        ((p[0] == 'O') && (p[1] == 'P') && (p[2] == 'T') && (p[3] == 'I') && (p[4] == 'O') && (p[5] == 'N') && (p[6] == 'S') && (p[7] == ' ') && (p[8] == '/'))   // OPTIONS
    ) {
        *packet_type = PACKET_TYPE_REQUEST;
        return 1;
    }

    return 0;
}

static __always_inline bool still_responding(http_info_t *info) {
    return info->status != 0;
}

static __always_inline bool still_reading(http_info_t *info) {
    return info->status == 0 && info->start_monotime_ns != 0;
}

static __always_inline u8 http_info_complete(http_info_t *info) {
    return (info->start_monotime_ns != 0 && info->status != 0 && info->pid.host_pid != 0);
}

static __always_inline u8 http_will_complete(http_info_t *info, unsigned char *buf, u32 len) {
    if (info->start_monotime_ns != 0) {
        u8 packet_type;
        unsigned char small_buf[MIN_HTTP2_SIZE];
        bpf_probe_read(small_buf, MIN_HTTP2_SIZE, (void *)buf);
        if (is_http(small_buf, len, &packet_type)) {
            return packet_type == PACKET_TYPE_RESPONSE;
        }
    }

    return false;
}

static __always_inline void finish_http(http_info_t *info, pid_connection_info_t *pid_conn) {
    if (http_info_complete(info)) {
        http_info_t *trace = bpf_ringbuf_reserve(&events, sizeof(http_info_t), 0);        
        if (trace) {
            bpf_dbg_printk("Sending trace %lx, response length %d", info, info->resp_len);

            bpf_memcpy(trace, info, sizeof(http_info_t));
            trace->flags = EVENT_K_HTTP_REQUEST;
            bpf_ringbuf_submit(trace, get_flags());
        }

        // bpf_dbg_printk("Terminating trace for pid=%d", pid_from_pid_tgid(pid_tid));
        // dbg_print_http_connection_info(&info->conn_info); // commented out since GitHub CI doesn't like this call
        bpf_map_delete_elem(&ongoing_http, pid_conn);
    }        
}

static __always_inline void update_http_sent_len(pid_connection_info_t *pid_conn, int sent_len) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    if (info) {        
        info->resp_len += sent_len;
    }
}

static __always_inline http_info_t *get_or_set_http_info(http_info_t *info, pid_connection_info_t *pid_conn, u8 packet_type) {
    if (packet_type == PACKET_TYPE_REQUEST) {
        http_info_t *old_info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
        if (old_info) {
            finish_http(old_info, pid_conn); // this will delete ongoing_http for this connection info if there's full stale request
        }

        bpf_map_update_elem(&ongoing_http, pid_conn, info, BPF_ANY);
    }

    return bpf_map_lookup_elem(&ongoing_http, pid_conn);
}

static __always_inline void finish_possible_delayed_http_request(pid_connection_info_t *pid_conn) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    if (info) {        
        finish_http(info, pid_conn);
    }
}

static __always_inline void set_fallback_http_info(http_info_t *info, connection_info_t *conn, int len) {
    info->start_monotime_ns = bpf_ktime_get_ns();
    info->status = 0;
    info->len = len;
    bpf_map_update_elem(&ongoing_http_fallback, conn, info, BPF_ANY);
}

static __always_inline void process_http_request(http_info_t *info, int len, http_connection_metadata_t *meta, int direction, u16 orig_dport) {
    // Set pid and type early as best effort in case the request times out or dies.
    if (meta) {
        info->pid = meta->pid;
        info->type = meta->type;
    } else {
        if (direction == TCP_RECV) {
            info->type = EVENT_HTTP_REQUEST;
        } else {
            info->type = EVENT_HTTP_CLIENT;
        }
        task_pid(&info->pid);
    }

    fixup_connection_info(&info->conn_info, info->type == EVENT_HTTP_CLIENT, orig_dport);

    info->start_monotime_ns = bpf_ktime_get_ns();
    info->status = 0;
    info->len = len;
    info->extra_id = extra_runtime_id(); // required for deleting the trace information
    info->task_tid = get_task_tid();     // required for deleting the trace information
}

static __always_inline void process_http_response(http_info_t *info, unsigned char *buf, int len) {
    info->resp_len = 0;
    info->end_monotime_ns = bpf_ktime_get_ns();
    info->status = 0;
    info->status += (buf[RESPONSE_STATUS_POS]     - '0') * 100;
    info->status += (buf[RESPONSE_STATUS_POS + 1] - '0') * 10;
    info->status += (buf[RESPONSE_STATUS_POS + 2] - '0');
    if (info->status > MAX_HTTP_STATUS) { // we read something invalid
        info->status = 0;
    }
}

static __always_inline void handle_http_response(unsigned char *small_buf, pid_connection_info_t *pid_conn, http_info_t *info, int orig_len, u8 direction, u8 ssl) {
    process_http_response(info, small_buf, orig_len);

    if ((direction != TCP_SEND) /*|| (ssl != NO_SSL) || (orig_len < KPROBES_LARGE_RESPONSE_LEN)*/) {
        finish_http(info, pid_conn);
    } else {
        if (ssl && (pid_conn->conn.s_port == 0) && (pid_conn->conn.d_port == 0)) {
            bpf_dbg_printk("Fake connection info, finishing request");
            finish_http(info, pid_conn);
        } else {
            bpf_dbg_printk("Delaying finish http for large request, orig_len %d", orig_len);
        }
    }
    
    if (info->type == EVENT_HTTP_REQUEST) {
        trace_key_t t_key = {0};
        t_key.extra_id = info->extra_id;
        t_key.p_key.ns = info->pid.ns;
        t_key.p_key.pid = info->task_tid;
        delete_server_trace(&t_key);
    } else {
        //bpf_dbg_printk("Deleting client trace map for connection");
        //dbg_print_http_connection_info(&pid_conn->conn);

        bpf_map_delete_elem(&trace_map, &pid_conn->conn);
    }
    bpf_map_delete_elem(&active_ssl_connections, pid_conn);
}

// TAIL_PROTOCOL_HTTP
SEC("kprobe/http")
int protocol_http(void *ctx) {
    call_protocol_args_t *args = protocol_args();

    if (!args) {
        return 0;
    }

    http_info_t *in = empty_http_info();
    if (!in) {
        bpf_dbg_printk("Error allocating http info from per CPU map");
        return 0;
    }

    bpf_memcpy(&in->conn_info, &args->pid_conn.conn, sizeof(connection_info_t));
    in->ssl = args->ssl;

    http_info_t *info = get_or_set_http_info(in, &args->pid_conn, args->packet_type);
    if (!info) {
        bpf_dbg_printk("No info, pid =%d?, looking for fallback...", args->pid_conn.pid);
        info = (http_info_t *)bpf_map_lookup_elem(&ongoing_http_fallback, &args->pid_conn.conn);
        if (!info) {
            bpf_dbg_printk("No fallback either, giving up");
            //dbg_print_http_connection_info(&pid_conn->conn); // commented out since GitHub CI doesn't like this call
            return 0;
        }
    } 

    bpf_dbg_printk("=== http_buffer_event len=%d pid=%d still_reading=%d ===", args->bytes_len, pid_from_pid_tgid(bpf_get_current_pid_tgid()), still_reading(info));

    if (args->packet_type == PACKET_TYPE_REQUEST && (info->status == 0) && (info->start_monotime_ns == 0)) {
        http_connection_metadata_t *meta = connection_meta_by_direction(&args->pid_conn, args->direction, PACKET_TYPE_REQUEST);

        get_or_create_trace_info(meta, args->pid_conn.pid, &args->pid_conn.conn, (void *)args->u_buf, args->bytes_len, capture_header_buffer);

        if (meta) {            
            tp_info_pid_t *tp_p = trace_info_for_connection(&args->pid_conn.conn);
            if (tp_p) {
                info->tp = tp_p->tp;

                if (meta->type == EVENT_HTTP_CLIENT && !valid_span(tp_p->tp.parent_id)) {
                    bpf_dbg_printk("Looking for trace id of a client span");                        
                    tp_info_pid_t *server_tp = find_parent_trace();
                    if (server_tp && server_tp->valid) {
                        bpf_dbg_printk("Found existing server span for id=%llx", bpf_get_current_pid_tgid());
                        bpf_memcpy(info->tp.trace_id, server_tp->tp.trace_id, sizeof(info->tp.trace_id));
                        bpf_memcpy(info->tp.parent_id, server_tp->tp.span_id, sizeof(info->tp.parent_id));
                    } else {
                        bpf_dbg_printk("Cannot find server span for id=%llx", bpf_get_current_pid_tgid());
                    }
                }
            } else {
                bpf_dbg_printk("Can't find trace info, this is a bug!");
            }
        } else {
            bpf_dbg_printk("No META!");
        }

        // we copy some small part of the buffer to the info trace event, so that we can process an event even with
        // incomplete trace info in user space.
        bpf_probe_read(info->buf, FULL_BUF_SIZE, (void *)args->u_buf);
        process_http_request(info, args->bytes_len, meta, args->direction, args->orig_dport);
    } else if ((args->packet_type == PACKET_TYPE_RESPONSE) && (info->status == 0)) {
        handle_http_response(args->small_buf, &args->pid_conn, info, args->bytes_len, args->direction, args->ssl);
    } else if (still_reading(info)) {
        info->len += args->bytes_len;
    }   

    bpf_map_delete_elem(&ongoing_http_fallback, &args->pid_conn.conn);

    return 0;
}


#endif