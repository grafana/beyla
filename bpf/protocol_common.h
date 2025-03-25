#ifndef PROTOCOL_HELPERS
#define PROTOCOL_HELPERS

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "http_types.h"
#include "ringbuf.h"
#include "bpf_dbg.h"
#include "pin_internal.h"

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
    __type(key, pid_connection_info_t); // connection that's SSL
    __type(value, u64);                 // ssl
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} active_ssl_connections SEC(".maps");

static __always_inline http_connection_metadata_t *empty_connection_meta() {
    int zero = 0;
    return bpf_map_lookup_elem(&connection_meta_mem, &zero);
}

static __always_inline u8 *iovec_memory() {
    int zero = 0;
    return bpf_map_lookup_elem(&iovec_mem, &zero);
}

static __always_inline call_protocol_args_t *protocol_args() {
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

static __always_inline http_connection_metadata_t *
connection_meta_by_direction(pid_connection_info_t *pid_conn, u8 direction, u8 packet_type) {
    http_connection_metadata_t *meta = empty_connection_meta();
    if (!meta) {
        return 0;
    }

    meta->type = request_type_by_direction(direction, packet_type);
    task_pid(&meta->pid);

    return meta;
}

struct iov_iter___dummy {
    unsigned int type; // for co-re support, use iter_type instead
    u8 iter_type;
    void *ubuf;
    const struct iovec *iov;
    const struct iovec *__iov;
    unsigned long nr_segs;
};

typedef struct iov_iter___dummy iovec_iter_ctx;

enum iter_type___dummy { ITER_UBUF };

// extracts kernel specific iov_iter information into a iovec_iter_ctx instance
static __always_inline void get_iovec_ctx(iovec_iter_ctx *ctx, struct msghdr *msg) {
    ctx->ubuf = NULL;
    ctx->iov = NULL;
    if (bpf_core_field_exists(((struct iov_iter___dummy *)&msg->msg_iter)->type)) {
        // clear the direction bit when reading iovec_iter::type to end up
        // with the original enumerator value (the direction bit is the LSB
        // and is either 0 (READ) or 1 (WRITE)).
        ctx->iter_type = BPF_CORE_READ((struct iov_iter___dummy *)&msg->msg_iter, type) & 0xfe;
    } else {
        ctx->iter_type = BPF_CORE_READ((struct iov_iter___dummy *)&msg->msg_iter, iter_type);
    }

    if (bpf_core_field_exists(((struct iov_iter___dummy *)&msg->msg_iter)->ubuf)) {
        ctx->ubuf = BPF_CORE_READ((struct iov_iter___dummy *)&msg->msg_iter, ubuf);
    }

    if (bpf_core_field_exists(((struct iov_iter___dummy *)&msg->msg_iter)->iov)) {
        ctx->iov = BPF_CORE_READ((struct iov_iter___dummy *)&msg->msg_iter, iov);
    } else if (bpf_core_field_exists(((struct iov_iter___dummy *)&msg->msg_iter)->__iov)) {
        ctx->iov = BPF_CORE_READ((struct iov_iter___dummy *)&msg->msg_iter, __iov);
    }

    ctx->nr_segs = BPF_CORE_READ((struct iov_iter___dummy *)&msg->msg_iter, nr_segs);
}

static __always_inline int read_iovec_ctx(iovec_iter_ctx *ctx, u8 *buf, size_t max_len) {
    if (max_len == 0) {
        return 0;
    }

    bpf_clamp_umax(max_len, IO_VEC_MAX_LEN);

    bpf_dbg_printk("iter_type=%u", ctx->iter_type);
    bpf_dbg_printk("nr_segs=%lu, iov=%p, ubuf=%p", ctx->nr_segs, ctx->iov, ctx->ubuf);

    // ITER_UBUF only exists in kernels >= 6.0 - earlier kernels use ITER_IOVEC
    if (bpf_core_enum_value_exists(enum iter_type___dummy, ITER_UBUF)) {
        const int iter_ubuf = bpf_core_enum_value(enum iter_type___dummy, ITER_UBUF);

        // ITER_UBUF is never a bitmask, and can be 0, so we perform a proper
        // equality check rather than a bitwise and like we do for ITER_IOVEC
        if (ctx->ubuf != NULL && ctx->iter_type == iter_ubuf) {
            bpf_clamp_umax(max_len, IO_VEC_MAX_LEN);
            return bpf_probe_read(buf, max_len, ctx->ubuf) == 0 ? max_len : 0;
        }
    }

    const int iter_iovec = bpf_core_enum_value(enum iter_type, ITER_IOVEC);

    if (ctx->iter_type != iter_iovec) {
        return 0;
    }

    u32 tot_len = 0;

    enum { max_segments = 16 };

    bpf_clamp_umax(ctx->nr_segs, max_segments);

    // Loop couple of times reading the various io_vecs
    for (unsigned long i = 0; i < ctx->nr_segs && i < max_segments; i++) {
        struct iovec vec;

        if (bpf_probe_read_kernel(&vec, sizeof(vec), &ctx->iov[i]) != 0) {
            break;
        }

        // bpf_dbg_printk("iov[%d]=%llx", i, &ctx->iov[i]);
        // bpf_dbg_printk("base %llx, len %d", vec.iov_base, vec.iov_len);

        if (!vec.iov_base || !vec.iov_len) {
            continue;
        }

        const u32 remaining = IO_VEC_MAX_LEN > tot_len ? (IO_VEC_MAX_LEN - tot_len) : 0;
        u32 iov_size = vec.iov_len < max_len ? vec.iov_len : max_len;
        iov_size = iov_size < remaining ? iov_size : remaining;
        bpf_clamp_umax(tot_len, IO_VEC_MAX_LEN);
        bpf_clamp_umax(iov_size, IO_VEC_MAX_LEN);

        // bpf_dbg_printk("tot_len=%d, remaining=%d", tot_len, remaining);

        if (tot_len + iov_size > max_len) {
            break;
        }

        bpf_probe_read(&buf[tot_len], iov_size, vec.iov_base);

        // bpf_dbg_printk("iov_size=%d, buf=%s", iov_size, buf);

        tot_len += iov_size;
    }

    return tot_len;
}

static __always_inline int read_msghdr_buf(struct msghdr *msg, u8 *buf, size_t max_len) {
    if (max_len == 0) {
        return 0;
    }

    iovec_iter_ctx ctx;

    get_iovec_ctx(&ctx, msg);

    return read_iovec_ctx(&ctx, buf, max_len);
}

// We sort the connection info to ensure we can track requests and responses. However, if the destination port
// is somehow in the ephemeral port range, it can be higher than the source port and we'd use the sorted connection
// info in user space, effectively reversing the flow of the operation. We keep track of the original destination port
// and we undo the swap in the data collections we send to user space.
static __always_inline void
fixup_connection_info(connection_info_t *conn_info, u8 client, u16 orig_dport) {
    // The destination port is the server port in userspace
    if ((client && conn_info->d_port != orig_dport) ||
        (!client && conn_info->d_port == orig_dport)) {
        bpf_dbg_printk("Swapped connection info for userspace, client = %d, orig_dport = %d",
                       client,
                       orig_dport);
        swap_connection_info_order(conn_info);
        //dbg_print_http_connection_info(conn_info); // commented out since GitHub CI doesn't like this call
    }
}

#endif
