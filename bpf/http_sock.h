#ifndef HTTP_SOCK_HELPERS
#define HTTP_SOCK_HELPERS

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "http_types.h"
#include "ringbuf.h"
#include "pid.h"

#define MIN_HTTP_SIZE 12 // HTTP/1.1 CCC is the smallest valid request we can have
#define RESPONSE_STATUS_POS 9 // HTTP/1.1 <--

#define PACKET_TYPE_REQUEST 1
#define PACKET_TYPE_RESPONSE 2

// Keeps track of the tcp sequences we've seen for a connection
// With multiple network interfaces the same sequence can be seen again
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, u32); // the TCP sequence
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} http_tcp_seq SEC(".maps");

// Keeps track of active accept or connect connection infos
// From this table we extract the PID of the process and filter
// HTTP calls we are not interested in
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, http_connection_metadata_t); // PID_TID group and connection type
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} filtered_connections SEC(".maps");

// Keeps track of the ongoing http connections we match for request/response
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, http_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_http SEC(".maps");

static __always_inline bool tcp_dup(connection_info_t *http, protocol_info_t *tcp) {
    u32 *prev_seq = bpf_map_lookup_elem(&http_tcp_seq, http);

    if (prev_seq && (*prev_seq == tcp->seq)) {
        return true;
    }

    bpf_map_update_elem(&http_tcp_seq, http, &tcp->seq, BPF_ANY);
    return false;
}

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

static __always_inline void *read_msghdr_buf(struct msghdr *msg) {
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

// Copying 16 bytes at a time from the skb buffer is the only way to keep the verifier happy.
static __always_inline void read_skb_bytes(const void *skb, u32 offset, unsigned char *buf, const u32 len) {
    u32 max = offset + len;
    int b = 0;
    for (; b < (FULL_BUF_SIZE/BUF_COPY_BLOCK_SIZE); b++) {
        if ((offset + (BUF_COPY_BLOCK_SIZE - 1)) >= max) {
            break;
        }
        bpf_skb_load_bytes(skb, offset, (void *)(&buf[b * BUF_COPY_BLOCK_SIZE]), BUF_COPY_BLOCK_SIZE);
        offset += BUF_COPY_BLOCK_SIZE;
    }

    if ((b * BUF_COPY_BLOCK_SIZE) >= len) {
        return;
    }

    // This code is messy to make sure the eBPF verifier is happy. I had to cast to signed 64bit.
    s64 remainder = (s64)max - (s64)offset;

    if (remainder <= 0) {
        return;
    }

    int remaining_to_copy = (remainder < (BUF_COPY_BLOCK_SIZE - 1)) ? remainder : (BUF_COPY_BLOCK_SIZE - 1);
    int space_in_buffer = (len < (b * BUF_COPY_BLOCK_SIZE)) ? 0 : len - (b * BUF_COPY_BLOCK_SIZE);

    if (remaining_to_copy <= space_in_buffer) {
        bpf_skb_load_bytes(skb, offset, (void *)(&buf[b * BUF_COPY_BLOCK_SIZE]), remaining_to_copy);
    }
}

static __always_inline void finish_http(http_info_t *info) {
    if (info->start_monotime_ns != 0 && info->status != 0 && info->pid != 0) {
        http_info_t *trace = bpf_ringbuf_reserve(&events, sizeof(http_info_t), 0);
        if (trace) {
            bpf_dbg_printk("Sending trace %lx", info);

            bpf_memcpy(trace, info, sizeof(http_info_t));
            bpf_ringbuf_submit(trace, get_flags());
        }

        bpf_map_delete_elem(&http_tcp_seq, &info->conn_info);
        bpf_map_delete_elem(&ongoing_http, &info->conn_info);
        // bpf_map_delete_elem(&filtered_connections, &info->conn_info); // don't clean this up, doesn't work with keepalive
    }        
}

static __always_inline http_info_t *get_or_set_http_info(http_info_t *info, u8 packet_type) {
    if (packet_type == PACKET_TYPE_REQUEST) {
        http_info_t *old_info = bpf_map_lookup_elem(&ongoing_http, &info->conn_info);
        if (old_info) {
            finish_http(old_info); // this will delete ongoing_http for this connection info if there's full stale request
        }

        bpf_map_update_elem(&ongoing_http, &info->conn_info, info, BPF_ANY);
    }

    return bpf_map_lookup_elem(&ongoing_http, &info->conn_info);
}

static __always_inline bool still_responding(http_info_t *info) {
    return info->status != 0;
}

static __always_inline bool still_reading(http_info_t *info) {
    return info->status == 0 && info->start_monotime_ns != 0;
}

static __always_inline void process_http_request(http_info_t *info) {
    info->start_monotime_ns = bpf_ktime_get_ns();
    info->status = 0;
    info->len = 0;
}

static __always_inline void process_http_response(http_info_t *info, unsigned char *buf, http_connection_metadata_t *meta) {
    info->pid = pid_from_pid_tgid(meta->id);
    info->type = meta->type;
    info->status = 0;
    info->status += (buf[RESPONSE_STATUS_POS]     - '0') * 100;
    info->status += (buf[RESPONSE_STATUS_POS + 1] - '0') * 10;
    info->status += (buf[RESPONSE_STATUS_POS + 2] - '0');
}

static __always_inline void process_http(http_info_t *in, protocol_info_t *tcp, u8 packet_type, u32 packet_len, unsigned char *buf, http_connection_metadata_t *meta) {
    http_info_t *info = get_or_set_http_info(in, packet_type);
    if (!info || info->ssl) {
        return;
    }

    if (packet_type == PACKET_TYPE_REQUEST) {
        process_http_request(info);
    } else if (packet_type == PACKET_TYPE_RESPONSE) {
        process_http_response(info, buf, meta);
    }

    if (still_reading(info)) {
        info->len += packet_len;
    }

    if (still_responding(info)) {
        info->end_monotime_ns = bpf_ktime_get_ns();
    }

    if (tcp_close(tcp)) {
        finish_http(info);
    }

}

#endif