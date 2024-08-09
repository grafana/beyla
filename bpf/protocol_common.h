#ifndef PROTOCOL_HELPERS
#define PROTOCOL_HELPERS

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "http_types.h"
#include "ringbuf.h"
#include "pid.h"
#include "bpf_dbg.h"

#define MIN_HTTP_SIZE  12 // HTTP/1.1 CCC is the smallest valid request we can have
#define RESPONSE_STATUS_POS 9 // HTTP/1.1 <--
#define MAX_HTTP_STATUS 599

#define PACKET_TYPE_REQUEST 1
#define PACKET_TYPE_RESPONSE 2

#define IO_VEC_MAX_LEN 512

volatile const s32 capture_header_buffer = 0;

extern int LINUX_KERNEL_VERSION __kconfig;

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
struct iov_iter___v64 {
    u8 iter_type;
    bool nofault;
    bool data_source;
    size_t iov_offset;
    union {
        struct iovec __ubuf_iovec;
        struct {
            union {
                /* use iter_iov() to get the current vec */
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

struct iov_iter___v60 {
    u8 iter_type;
    bool nofault;
    bool data_source;
    bool user_backed;
    union {
        size_t iov_offset;
        int last_offset;
    };
    size_t count;
    union {
        const struct iovec *iov;
        const struct kvec *kvec;
        const struct bio_vec *bvec;
        struct xarray *xarray;
        struct pipe_inode_info *pipe;
        void *ubuf;
    };
    union {
        unsigned long nr_segs;
        struct {
            unsigned int head;
            unsigned int start_head;
        };
        loff_t xarray_start;
    };
};


// older struct that features 'type' instead of 'iter_type'
struct iov_iter___v58 {
    unsigned int type;
    size_t iov_offset;
    size_t count;
    union {
        const struct iovec *iov;
        const struct kvec *kvec;
        const struct bio_vec *bvec;
        struct pipe_inode_info *pipe;
    };
    union {
        unsigned long nr_segs;
        struct {
            unsigned int head;
            unsigned int start_head;
        };
    };
};

// helper struct used by get_iovec_ctx
struct iovec_iter_ctx {
    unsigned int iter_type;
    size_t iov_offset;
    size_t count;
    unsigned long nr_segs;
    const struct iovec *iov;
    const void *ubuf;
};

// extracts kernel specific iov_iter information into a iovec_iter_ctx instance
static __always_inline void get_iovec_ctx(struct iovec_iter_ctx* ctx, struct msghdr *msg) {
    if (LINUX_KERNEL_VERSION <= KERNEL_VERSION(5, 13, 0)) {
        struct iov_iter___v58 iter;
        bpf_core_read(&iter, sizeof(iter), &msg->msg_iter);

        ctx->iter_type = iter.type;
        ctx->iov_offset = iter.iov_offset;
        ctx->count = iter.count;
        ctx->nr_segs = iter.nr_segs;
        ctx->iov = iter.iov;
        ctx->ubuf = NULL;
    } else if (LINUX_KERNEL_VERSION <= KERNEL_VERSION(6, 3, 0)) {
        struct iov_iter___v60 iter;
        bpf_core_read(&iter, sizeof(iter), &msg->msg_iter);

        ctx->iter_type = iter.iter_type & 0xff;
        ctx->iov_offset = iter.iov_offset;
        ctx->count = iter.count;
        ctx->nr_segs = iter.nr_segs;
        ctx->iov = iter.iov;
        ctx->ubuf = iter.ubuf;
    } else {
        struct iov_iter___v64 iter;
        bpf_core_read(&iter, sizeof(iter), &msg->msg_iter);

        ctx->iter_type = iter.iter_type & 0xff;
        ctx->iov_offset = iter.iov_offset;
        ctx->count = iter.count;
        ctx->nr_segs = iter.nr_segs;
        ctx->iov = iter.__iov;
        ctx->ubuf = iter.ubuf;
    }
}

static __always_inline int read_msghdr_buf(struct msghdr *msg, u8* buf, size_t max_len) {
    if (max_len == 0) {
        return 0;
    }

    bpf_clamp_umax(max_len, IO_VEC_MAX_LEN);

    struct iovec_iter_ctx ctx;

    get_iovec_ctx(&ctx, msg);

    const int iter_ubuf = LINUX_KERNEL_VERSION > KERNEL_VERSION(6, 7, 0) ? 0 : 6;

    bpf_printk("t=%u, off=%llu, count=%llu", ctx.iter_type, ctx.iov_offset, ctx.count);
    bpf_printk("nr_segs=%lu, iov=%p, ubuf=%p", ctx.nr_segs, ctx.iov, ctx.ubuf);

    if (ctx.count == 0)
        return 0;

    if (ctx.count > max_len)
        ctx.count = max_len;

    // ITER_UBUF only exists in kernels >= 6.0 - earlier kernels use ITER_IOVEC
    if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(6, 0, 0) && ctx.iter_type == iter_ubuf) {
        return bpf_probe_read(buf, ctx.count, ctx.ubuf) == 0 ? ctx.count : 0;
    }

    if ((ctx.iter_type & ITER_IOVEC) != ITER_IOVEC) {
        return 0;
    }

    bpf_clamp_umax(ctx.nr_segs, 4);

    u32 tot_len = 0;

    // Loop couple of times reading the various io_vecs
    for (int i = 0; i < ctx.nr_segs; i++) {
        struct iovec vec;

        if (bpf_probe_read_kernel(&vec, sizeof(vec), &ctx.iov[i]) != 0)
            return 0;

        bpf_dbg_printk("iov[%d]=%llx", i, &ctx.iov[i]);
        bpf_dbg_printk("base %llx, len %d", vec.iov_base, vec.iov_len);

        if (!vec.iov_base || !vec.iov_len) {
            continue;
        }

        const u32 remaining = IO_VEC_MAX_LEN > tot_len ? (IO_VEC_MAX_LEN - tot_len) : 0;
        u32 iov_size = vec.iov_len < max_len ? vec.iov_len : max_len;
        iov_size = iov_size < remaining ? iov_size : remaining;
        bpf_clamp_umax(tot_len, IO_VEC_MAX_LEN);
        bpf_clamp_umax(iov_size, IO_VEC_MAX_LEN);

        bpf_dbg_printk("tot_len=%d, remaining=%d", tot_len, remaining);

        if (tot_len + iov_size > max_len) {
            break;
        }

        bpf_probe_read(&buf[tot_len], iov_size, vec.iov_base);

        bpf_dbg_printk("iov_size=%d, buf=%s", iov_size, buf);

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
