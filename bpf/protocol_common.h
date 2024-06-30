#ifndef PROTOCOL_HELPERS
#define PROTOCOL_HELPERS

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "http_types.h"
#include "ringbuf.h"
#include "pid.h"

#define MIN_HTTP_SIZE  12 // HTTP/1.1 CCC is the smallest valid request we can have
#define RESPONSE_STATUS_POS 9 // HTTP/1.1 <--
#define MAX_HTTP_STATUS 599

#define PACKET_TYPE_REQUEST 1
#define PACKET_TYPE_RESPONSE 2

#define IO_VEC_MAX_LEN 512

volatile const s32 capture_header_buffer = 0;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, http_connection_metadata_t);
    __uint(max_entries, 1);
} connection_meta_mem SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, u8[(IO_VEC_MAX_LEN * 2)]);
    __uint(max_entries, 1);
} iovec_mem SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, call_protocol_args_t);
    __uint(max_entries, 1);
} protocol_args_mem SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t);   // connection that's SSL
    __type(value, u64); // ssl
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} active_ssl_connections SEC(".maps");

static __always_inline http_connection_metadata_t* empty_connection_meta() {
    int zero = 0;
    return bpf_map_lookup_elem(&connection_meta_mem, &zero);
}

static __always_inline u8* iovec_memory() {
    int zero = 0;
    return bpf_map_lookup_elem(&iovec_mem, &zero);
}

static __always_inline call_protocol_args_t* protocol_args() {
    int zero = 0;
    return bpf_map_lookup_elem(&protocol_args_mem, &zero);
}

static __always_inline u8 request_type_by_direction(u8 direction, u8 packet_type) {
    if (packet_type == PACKET_TYPE_RESPONSE) {
        if (direction == TCP_RECV) {
            return EVENT_HTTP_CLIENT;
        } else {
            return EVENT_HTTP_REQUEST;
        }
    } else {
        if (direction == TCP_RECV) {
            return EVENT_HTTP_REQUEST;
        } else {
            return EVENT_HTTP_CLIENT;
        }
    }

    return 0;
}

static __always_inline http_connection_metadata_t *connection_meta_by_direction(pid_connection_info_t *pid_conn, u8 direction, u8 packet_type) {
    http_connection_metadata_t *meta = empty_connection_meta();
    if (!meta) {
        return 0;
    }

    meta->type = request_type_by_direction(direction, packet_type);
    task_pid(&meta->pid);

    return meta;
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
    union {
		unsigned long nr_segs;
		loff_t xarray_start;
	};
};


static __always_inline int read_msghdr_buf(struct msghdr *msg, u8* buf, int max_len) {
    struct iov_iter msg_iter = BPF_CORE_READ(msg, msg_iter);
    u8 msg_iter_type = 0;

    if (bpf_core_field_exists(msg_iter.iter_type)) {
        bpf_probe_read(&msg_iter_type, sizeof(u8), &(msg_iter.iter_type));
        bpf_dbg_printk("msg iter type exists, read value %d", msg_iter_type);
    }

    bpf_dbg_printk("iter type %d", msg_iter_type);

    struct iovec *iov = NULL;

    u32 l = max_len;
    bpf_clamp_umax(l, IO_VEC_MAX_LEN);

    if (bpf_core_field_exists(msg_iter.iov)) {
        bpf_probe_read(&iov, sizeof(struct iovec *), &(msg_iter.iov));
        bpf_dbg_printk("iov exists, read value %llx", iov);
    } else {
        // TODO: I wonder if there's a way to check for field existence without having to
        // make fake structures that match the new version of the kernel code. This code
        // here assumes the kernel iov_iter structure is the format with __iov and __ubuf_iovec.
        struct _iov_iter _msg_iter;
        bpf_probe_read_kernel(&_msg_iter, sizeof(struct _iov_iter), &(msg->msg_iter));

        bpf_dbg_printk("new kernel, iov doesn't exist, nr_segs %d", _msg_iter.nr_segs);
        if (msg_iter_type == 5) {
            struct iovec vec;
            bpf_probe_read(&vec, sizeof(struct iovec), &(_msg_iter.__ubuf_iovec));
            bpf_dbg_printk("ubuf base %llx, &ubuf base %llx", vec.iov_base, &vec.iov_base);

            bpf_probe_read(buf, l, vec.iov_base);
            return l;
        } else {
            bpf_probe_read(&iov, sizeof(struct iovec *), &(_msg_iter.__iov));
        }     
    }
    
    if (!iov) {
        return 0;
    }

    if (msg_iter_type == 6) {// Direct char buffer
        bpf_dbg_printk("direct char buffer type=6 iov %llx", iov);
        bpf_probe_read(buf, l, iov);

        return l;
    }

    struct iovec vec;
    bpf_probe_read(&vec, sizeof(struct iovec), iov);

    bpf_dbg_printk("standard iov %llx base %llx len %d", iov, vec.iov_base, vec.iov_len);

    u32 tot_len = 0;

    // Loop couple of times reading the various io_vecs
    for (int i = 0; i < 4; i++) {
        void *p = &iov[i];
        bpf_probe_read(&vec, sizeof(struct iovec), p);
        // No prints in loops on 5.10
        // bpf_printk("iov[%d]=%llx base %llx, len %d", i, p, vec.iov_base, vec.iov_len);
        if (!vec.iov_base || !vec.iov_len) {
            continue;
        }

        u32 remaining = IO_VEC_MAX_LEN > tot_len ? (IO_VEC_MAX_LEN - tot_len) : 0;
        u32 iov_size = vec.iov_len < l ? vec.iov_len : l;
        iov_size = iov_size < remaining ? iov_size : remaining;
        bpf_clamp_umax(tot_len, IO_VEC_MAX_LEN);
        bpf_clamp_umax(iov_size, IO_VEC_MAX_LEN);
        // bpf_printk("tot_len=%d, remaining=%d", tot_len, remaining);
        if (tot_len + iov_size > l) {
            break;
        }
        bpf_probe_read(&buf[tot_len], iov_size, vec.iov_base);    
        // bpf_printk("iov_size=%d, buf=%s", iov_size, buf);

        tot_len += iov_size;
    }

    return tot_len;
}

// We sort the connection info to ensure we can track requests and responses. However, if the destination port
// is somehow in the ephemeral port range, it can be higher than the source port and we'd use the sorted connection
// info in user space, effectively reversing the flow of the operation. We keep track of the original destination port
// and we undo the swap in the data collections we send to user space.
static __always_inline void fixup_connection_info(connection_info_t *conn_info, u8 client, u16 orig_dport) {
    // The destination port is the server port in userspace
    if ((client && conn_info->d_port != orig_dport) || 
        (!client && conn_info->d_port == orig_dport)) {
        bpf_dbg_printk("Swapped connection info for userspace, client = %d, orig_dport = %d", client, orig_dport);
        swap_connection_info_order(conn_info);
        //dbg_print_http_connection_info(conn_info); // commented out since GitHub CI doesn't like this call
    }
}

#endif
