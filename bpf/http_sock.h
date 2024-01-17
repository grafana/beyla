#ifndef HTTP_SOCK_HELPERS
#define HTTP_SOCK_HELPERS

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "http_types.h"
#include "ringbuf.h"
#include "pid.h"
#include "trace_common.h"

#define MIN_HTTP_SIZE 12 // HTTP/1.1 CCC is the smallest valid request we can have
#define RESPONSE_STATUS_POS 9 // HTTP/1.1 <--

#define PACKET_TYPE_REQUEST 1
#define PACKET_TYPE_RESPONSE 2

volatile const s32 capture_header_buffer = 0;

// Keeps track of the ongoing http connections we match for request/response
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t);
    __type(value, http_info_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ongoing_http SEC(".maps");

// http_info_t became too big to be declared as a variable in the stack.
// We use a percpu array to keep a reusable copy of it
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, http_info_t);
    __uint(max_entries, 1);
} http_info_mem SEC(".maps");

static __always_inline bool is_http(unsigned char *p, u32 len, u8 *packet_type) {
    if (len < MIN_HTTP_SIZE) {
        return false;
    }
    //HTTP
    if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
       *packet_type = PACKET_TYPE_RESPONSE;
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
    }

    return true;
}

// Newer version of uio.h iov_iter than what we have in vmlinux.h.
struct _iov_iter {
	u8 iter_type;
	bool copy_mc;
	bool nofault;
	bool data_source;
	bool user_backed;
	union {
		size_t iov_offset;
		int last_offset;
	};
	union {
		struct iovec __ubuf_iovec;
		struct {
			union {
				const struct iovec *__iov;
				const struct kvec *kvec;
				const struct bio_vec *bvec;
				struct xarray *xarray;
				void *ubuf;
			};
			size_t count;
		};
	};
};

static __always_inline void *find_msghdr_buf(struct msghdr *msg) {
    unsigned int m_flags;
    struct iov_iter msg_iter;

    bpf_probe_read_kernel(&m_flags, sizeof(unsigned int), &(msg->msg_flags));
    bpf_probe_read_kernel(&msg_iter, sizeof(struct iov_iter), &(msg->msg_iter));

    u8 msg_iter_type = 0;

    if (bpf_core_field_exists(msg_iter.iter_type)) {
        bpf_probe_read(&msg_iter_type, sizeof(u8), &(msg_iter.iter_type));
        bpf_dbg_printk("msg iter type exists, read value %d", msg_iter_type);
    }

    bpf_dbg_printk("msg type %x, iter type %d", m_flags, msg_iter_type);

    struct iovec *iov = NULL;

    if (bpf_core_field_exists(msg_iter.iov)) {
        bpf_probe_read(&iov, sizeof(struct iovec *), &(msg_iter.iov));
        bpf_dbg_printk("iov exists, read value %llx", iov);
    } else {
        // TODO: I wonder if there's a way to check for field existence without having to
        // make fake structures that match the new version of the kernel code. This code
        // here assumes the kernel iov_iter structure is the format with __iov and __ubuf_iovec.
        struct _iov_iter _msg_iter;
        bpf_probe_read_kernel(&_msg_iter, sizeof(struct _iov_iter), &(msg->msg_iter));
        
        bpf_dbg_printk("new kernel, iov doesn't exist");

        if (msg_iter_type == 5) {
            struct iovec vec;
            bpf_probe_read(&vec, sizeof(struct iovec), &(_msg_iter.__ubuf_iovec));
            bpf_dbg_printk("ubuf base %llx", vec.iov_base);

            return vec.iov_base;
        } else {
            bpf_probe_read(&iov, sizeof(struct iovec *), &(_msg_iter.__iov));
        }     
    }
    
    if (!iov) {
        return NULL;
    }

    if (msg_iter_type == 6) {// Direct char buffer
        bpf_dbg_printk("direct char buffer type=6 iov %llx", iov);
        return iov;
    }

    struct iovec vec;
    bpf_probe_read(&vec, sizeof(struct iovec), iov);

    bpf_dbg_printk("standard iov %llx base %llx", iov, vec.iov_base);

    return vec.iov_base;    
}

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

static __always_inline void finish_http(http_info_t *info) {
    if (info->start_monotime_ns != 0 && info->status != 0 && info->pid.host_pid != 0) {
        http_info_t *trace = bpf_ringbuf_reserve(&events, sizeof(http_info_t), 0);        
        if (trace) {
            bpf_dbg_printk("Sending trace %lx", info);

            bpf_memcpy(trace, info, sizeof(http_info_t));
            bpf_ringbuf_submit(trace, get_flags());
        }

        u64 pid_tid = bpf_get_current_pid_tgid();
        bpf_map_delete_elem(&server_traces, &pid_tid);

        // bpf_dbg_printk("Terminating trace for pid=%d", pid_from_pid_tgid(pid_tid));
        // dbg_print_http_connection_info(&info->conn_info); // commented out since GitHub CI doesn't like this call
        pid_connection_info_t pid_conn = {
            .conn = info->conn_info,
            .pid = pid_from_pid_tgid(pid_tid)
        };

        bpf_map_delete_elem(&ongoing_http, &pid_conn);
    }        
}

static __always_inline http_info_t *get_or_set_http_info(http_info_t *info, pid_connection_info_t *pid_conn, u8 packet_type) {
    if (packet_type == PACKET_TYPE_REQUEST) {
        http_info_t *old_info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
        if (old_info) {
            finish_http(old_info); // this will delete ongoing_http for this connection info if there's full stale request
        }

        bpf_map_update_elem(&ongoing_http, pid_conn, info, BPF_ANY);
    }

    return bpf_map_lookup_elem(&ongoing_http, pid_conn);
}

static __always_inline bool still_responding(http_info_t *info) {
    return info->status != 0;
}

static __always_inline bool still_reading(http_info_t *info) {
    return info->status == 0 && info->start_monotime_ns != 0;
}

static __always_inline void process_http_request(http_info_t *info, int len) {
    info->start_monotime_ns = bpf_ktime_get_ns();
    info->status = 0;
    info->len = len;
}

static __always_inline void process_http_response(http_info_t *info, unsigned char *buf, http_connection_metadata_t *meta, int len) {
    info->pid = meta->pid;
    info->type = meta->type;
    info->resp_len = len;
    info->end_monotime_ns = bpf_ktime_get_ns();
    info->status = 0;
    info->status += (buf[RESPONSE_STATUS_POS]     - '0') * 100;
    info->status += (buf[RESPONSE_STATUS_POS + 1] - '0') * 10;
    info->status += (buf[RESPONSE_STATUS_POS + 2] - '0');
}

static __always_inline void handle_http_response(unsigned char *small_buf, pid_connection_info_t *pid_conn, http_info_t *info, int orig_len) {
    http_connection_metadata_t *meta = bpf_map_lookup_elem(&filtered_connections, pid_conn);
    http_connection_metadata_t dummy_meta = {
        .type = EVENT_HTTP_REQUEST
    };

    if (!meta) {
        task_pid(&dummy_meta.pid);
        meta = &dummy_meta;
    }

    process_http_response(info, small_buf, meta, orig_len);
    finish_http(info);
}

static __always_inline void send_http_trace_buf(void *u_buf, int size, connection_info_t *conn) {
    if (size <= 0) {
        return;
    }

    http_buf_t *trace = bpf_ringbuf_reserve(&events, sizeof(http_buf_t), 0);
    if (trace) {
        trace->conn_info = *conn;
        trace->flags |= CONN_INFO_FLAG_TRACE;

        s64 buf_len = (s64)size;
        if (buf_len >= TRACE_BUF_SIZE) {
            buf_len = TRACE_BUF_SIZE - 1;
        }
        buf_len &= (TRACE_BUF_SIZE - 1);
        bpf_probe_read(trace->buf, buf_len, u_buf);

        if (buf_len < TRACE_BUF_SIZE) {
            trace->buf[buf_len] = '\0';
        }
        
        bpf_dbg_printk("Sending http buffer %s", trace->buf);
        bpf_ringbuf_submit(trace, get_flags());
    }
}

static __always_inline void handle_buf_with_connection(pid_connection_info_t *pid_conn, void *u_buf, int bytes_len, u8 ssl) {
    unsigned char small_buf[MIN_HTTP_SIZE] = {0};
    bpf_probe_read(small_buf, MIN_HTTP_SIZE, u_buf);

    bpf_dbg_printk("buf=[%s], pid=%d", small_buf, pid_conn->pid);

    u8 packet_type = 0;
    if (is_http(small_buf, MIN_HTTP_SIZE, &packet_type)) {
        http_info_t *in = empty_http_info();
        if (!in) {
            bpf_dbg_printk("Error allocating http info from per CPU map");
            return;
        }
        in->conn_info = pid_conn->conn;
        in->ssl = ssl;

        http_info_t *info = get_or_set_http_info(in, pid_conn, packet_type);
        if (!info) {
            bpf_dbg_printk("No info, pid =%d?", pid_conn->pid);
            //dbg_print_http_connection_info(&pid_conn->conn); // commented out since GitHub CI doesn't like this call
            return;
        }

        bpf_dbg_printk("=== http_buffer_event len=%d pid=%d still_reading=%d ===", bytes_len, pid_from_pid_tgid(bpf_get_current_pid_tgid()), still_reading(info));

        if (packet_type == PACKET_TYPE_REQUEST && (info->status == 0)) {    
            http_connection_metadata_t *meta = bpf_map_lookup_elem(&filtered_connections, pid_conn);
            get_or_create_trace_info(meta, pid_conn->pid, &pid_conn->conn, u_buf, bytes_len, capture_header_buffer);

            if (!meta) {
                bpf_dbg_printk("No META!");
            }

            if (meta) {            
                tp_info_pid_t *tp_p = trace_info_for_connection(&pid_conn->conn);
                if (tp_p) {
                    info->tp = tp_p->tp;

                    if (meta->type == EVENT_HTTP_CLIENT && !valid_span(tp_p->tp.parent_id)) {
                        bpf_dbg_printk("Looking for trace id of a client span");
                        u64 pid_tid = bpf_get_current_pid_tgid();
                        tp_info_t *server_tp = bpf_map_lookup_elem(&server_traces, &pid_tid);
                        if (server_tp) {
                            bpf_dbg_printk("Found existing server span for id=%llx", pid_tid);
                            bpf_memcpy(info->tp.trace_id, server_tp->trace_id, sizeof(info->tp.trace_id));
                            bpf_memcpy(info->tp.parent_id, server_tp->span_id, sizeof(info->tp.parent_id));
                        } else {
                            bpf_dbg_printk("Cannot find server span for id=%llx", pid_tid);
                        }
                    }
                } else {
                    bpf_dbg_printk("Can't find trace info, this is a bug!");
                }
            }
            // we copy some small part of the buffer to the info trace event, so that we can process an event even with
            // incomplete trace info in user space.
            bpf_probe_read(info->buf, FULL_BUF_SIZE, u_buf);
            process_http_request(info, bytes_len);
        } else if (packet_type == PACKET_TYPE_RESPONSE) {
            handle_http_response(small_buf, pid_conn, info, bytes_len);
        } else if (still_reading(info)) {
            info->len += bytes_len;
        }       
    }
}

#endif