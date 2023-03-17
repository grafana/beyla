#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "instrumenter.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_CONCURRENT_REQUESTS 10000
#define AF_INET 2
#define AF_INET6 10

#define DEBUG
#undef DEBUG

// The PID we are tracking
volatile const uint active_pid;

// The set of file descriptors we are tracking.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, uint);
    __type(value, u8);
} active_fds SEC(".maps");

// The set of read/write buffers and file descriptors we are tracking.
struct data_args_t
{
    u64 fd;
    const char *buf;
    size_t *size;
};

struct addr_info_t
{
    struct sockaddr *addr;
    int fd;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, struct addr_info_t);
} active_addr_infos SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, struct data_args_t);
} active_read_args SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, u8);
} active_accept_ssl SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, struct data_args_t);
} active_read_ssl_args SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, struct data_args_t);
} active_write_ssl_args SEC(".maps");

// Used to capture socket file descriptor cloning
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, u32);
} fcntl_id_to_fd SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u32);
    __type(value, u32);
} fcntl_fd_to_fd SEC(".maps");

// Used to send events to the userspace instrumenter
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS *(MAX_MSG_SIZE + sizeof(struct attr_t)));
} events SEC(".maps");

// Helper functions
static __inline uint valid_pid(u64 id)
{
    u32 pid = id >> 32;
    if (pid != active_pid)
    {
        // some frameworks launch sub-processes for handling requests
        u32 host_ppid = 0;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task)
        {
            host_ppid = BPF_CORE_READ(task, real_parent, tgid);
        }

        if (host_ppid != active_pid)
        {
            return 0;
        }
    }

    return pid;
}

static __inline int peer_info_start(struct sockaddr *upeer_sockaddr, int save_fd)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    struct addr_info_t sock_info = {};
    sock_info.addr = upeer_sockaddr;
    sock_info.fd = save_fd;

    bpf_map_update_elem(&active_addr_infos, &id, &sock_info, BPF_ANY);

    return 0;
}

static __inline int peer_info_end(int event_type, uint ret)
{
    u64 id = bpf_get_current_pid_tgid();
    u8 t = 1;
    struct syscall_write_event_t *e;

    if (!valid_pid(id))
    {
        return 0;
    }

#ifdef DEBUG
    bpf_printk("accept4/getpeername %d", event_type);
#endif

    // The file descriptor is the value returned from the accept4 syscall.
    if ((int)ret < 0)
    {
        goto cleanup;
    }

    struct addr_info_t *sock_info = bpf_map_lookup_elem(&active_addr_infos, &id);
    if (!sock_info)
    {
        goto cleanup;
    }

    // reserve sample from BPF ringbuf
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("accept4: couldn't allocate ring buffer request");
        goto cleanup;
    }

    struct sockaddr sa;

    bpf_probe_read(&sa, sizeof(struct sockaddr), (void *)(sock_info->addr));

    e->attr.msg_size_or_type = sa.sa_family;
    if (sa.sa_family == AF_INET6)
    {
        struct sockaddr_in6 *daddr = (struct sockaddr_in6 *)&sa;
        bpf_probe_read(&e->msg, sizeof(struct in6_addr), &daddr->sin6_addr);
        bpf_probe_read(&e->attr.bytes, sizeof(u16), &daddr->sin6_port);
    }
    else if (sa.sa_family == AF_INET)
    {
        struct sockaddr_in *daddr = (struct sockaddr_in *)&sa;
        bpf_probe_read(&e->msg, sizeof(struct in_addr), &daddr->sin_addr);
        bpf_probe_read(&e->attr.bytes, sizeof(u16), &daddr->sin_port);
    }

    uint fd = sock_info->fd;

    if (event_type == kEventTypeSyscallAddrEvent)
    {
        fd = ret;
        bpf_map_update_elem(&active_fds, &fd, &t, BPF_ANY);
    }
    else
    {
        u32 *cloned_fd = bpf_map_lookup_elem(&fcntl_fd_to_fd, &fd);
        if (cloned_fd)
        {
            fd = *cloned_fd;
        }
    }

#ifdef DEBUG
    bpf_printk("accept4/getpeername fd=%d", fd);
#endif

    e->attr.event_type = event_type;
    e->attr.fd = fd;
    e->attr.ts = bpf_ktime_get_ns();
    e->attr.ssl_corr_id = id; // stash the full pid/thread id in case SSL doesn't have the file descriptor

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&active_addr_infos, &id);
    return 0;
}

SEC("kprobe/__sys_accept4")
int BPF_KPROBE(kprobe_accept4, int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen, int flags)
{
    return peer_info_start(upeer_sockaddr, -1);
}

SEC("kprobe/__sys_getpeername")
int BPF_KPROBE(kprobe_getpeername, int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen)
{
    return peer_info_start(upeer_sockaddr, fd);
}

SEC("kretprobe/__sys_accept4")
int BPF_KRETPROBE(kretprobe_accept4, uint fd)
{
    return peer_info_end(kEventTypeSyscallAddrEvent, fd);
}

SEC("kretprobe/__sys_getpeername")
int BPF_KRETPROBE(kretprobe_getpeername, uint ret)
{
    return peer_info_end(kEventTypeSyscallPeerNameEvent, ret);
}

SEC("kprobe/close_fd")
int BPF_KPROBE(kprobe_close, uint fd)
{
    struct syscall_write_event_t *e;
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

#ifdef DEBUG
    bpf_printk("close %d", fd);
#endif

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("close_fd: couldn't allocate ring buffer request");
        goto cleanup;
    }

    e->attr.event_type = kEventTypeSyscallCloseEvent;
    e->attr.fd = fd;
    e->attr.msg_size_or_type = 0;
    e->attr.bytes = 0;
    e->attr.ts = bpf_ktime_get_ns();
    e->attr.ssl_corr_id = id;

    bpf_ringbuf_submit(e, 0);

cleanup:
    bpf_map_delete_elem(&active_fds, &fd);
    bpf_map_delete_elem(&fcntl_fd_to_fd, &fd);
    bpf_map_delete_elem(&active_accept_ssl, &id);

    return 0;
}

static __inline int _ringbuf_handler(int event_type, u64 id, u64 fd, const char *buf, size_t count)
{
    // reserve sample from BPF ringbuf
    struct syscall_write_event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("couldn't allocate ring buffer request for type=%d", event_type);
        return 0;
    }

    e->attr.fd = fd;
    e->attr.bytes = count;
    size_t buf_size = count < sizeof(e->msg) ? count : sizeof(e->msg);
    bpf_probe_read(&e->msg, buf_size, (void *)buf);
    e->attr.msg_size_or_type = buf_size;
    e->attr.ts = bpf_ktime_get_ns();
    e->attr.ssl_corr_id = id;

    e->attr.event_type = event_type;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("kprobe/do_writev")
int BPF_KPROBE(kprobe_do_writev, uint fd, const struct iovec *vec, u64 vlen, u32 flags)
{
    struct syscall_write_event_t *e;
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    if (!bpf_map_lookup_elem(&active_fds, &fd))
    {
        // Bail early if we aren't tracking this fd.
        return 0;
    }

#ifdef DEBUG
    bpf_printk("writev fd=%d", fd);
#endif

    if (bpf_map_lookup_elem(&active_accept_ssl, &id))
    {
#ifdef DEBUG
        bpf_printk("SSL connection - ignore");
#endif
        return 0;
    }

    if (vec)
    {
        struct iovec vec_cpy = {};

        bpf_probe_read(&vec_cpy, sizeof(struct iovec), (void *)vec);

        return _ringbuf_handler(kEventTypeSyscallWriteEvent, id, fd, vec_cpy.iov_base, vec_cpy.iov_len);
    }

    return 0;
}

SEC("kprobe/ksys_write")
int BPF_KPROBE(kprobe_ksys_write, uint fd, const char *buf, size_t count)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    if (!bpf_map_lookup_elem(&active_fds, &fd))
    {
        // Bail early if we aren't tracking this fd.
        return 0;
    }

    if ((int)count <= 0)
    {
        return 0;
    }

#ifdef DEBUG
    bpf_printk("write fd=%d id=%ld", fd, id);
#endif

    if (bpf_map_lookup_elem(&active_accept_ssl, &id))
    {
#ifdef DEBUG
        bpf_printk("write SSL connection - ignore");
#endif
        return 0;
    }

    return _ringbuf_handler(kEventTypeSyscallWriteEvent, id, fd, buf, count);
}

SEC("kprobe/ksys_read")
int BPF_KPROBE(kprobe_ksys_read, uint fd, char *buf, size_t count)
{
    struct syscall_write_event_t *e;
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    if (!bpf_map_lookup_elem(&active_fds, &fd))
    {
        // Bail early if we aren't tracking this fd.
        return 0;
    }

    if (bpf_map_lookup_elem(&active_accept_ssl, &id))
    {
#ifdef DEBUG
        bpf_printk("SSL connection - ignore");
#endif
        return 0;
    }

    // stash these function arguments so we can use them upon return
    struct data_args_t read_args = {};
    read_args.fd = fd;
    read_args.buf = buf;

    bpf_map_update_elem(&active_read_args, &id, &read_args, BPF_ANY);

    return 0;
}

SEC("kretprobe/ksys_read")
int BPF_KRETPROBE(kretprobe_ksys_read, size_t count)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    if (((int)count) > 0)
    {
        struct syscall_write_event_t *e;
        struct data_args_t *args = bpf_map_lookup_elem(&active_read_args, &id);
        if (!args)
        {
            goto cleanup;
        }

        uint active_fd = args->fd;

        // check to see if this fd we are reading is actively tracked
        if (!bpf_map_lookup_elem(&active_fds, &active_fd))
        {
            goto cleanup;
        }

        // load the active buffer
        const char *active_buf = args->buf;
        if (!active_buf)
        {
            bpf_printk("no active buffer");
            goto cleanup;
        }

        _ringbuf_handler(kEventTypeSyscallReadEvent, id, active_fd, active_buf, count);
    }

cleanup:
    bpf_map_delete_elem(&active_read_args, &id);

    return 0;
}

SEC("uprobe/libssl.so:SSL_accept")
int BPF_UPROBE(uprobe_ssl_accept, void *ssl)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

#ifdef DEBUG
    bpf_printk("ssl accept");
#endif

    u8 t = 1;
    bpf_map_update_elem(&active_accept_ssl, &id, &t, BPF_ANY);

    return 0;
}

SEC("uprobe/libssl.so:SSL_do_handshake")
int BPF_UPROBE(uprobe_ssl_do_handshake, void *ssl)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

#ifdef DEBUG
    bpf_printk("ssl do handshake");
#endif

    u8 t = 1;
    bpf_map_update_elem(&active_accept_ssl, &id, &t, BPF_ANY);

    return 0;
}

static __inline int ssl_read_fd(void *ssl)
{
    struct ssl_st ssl_info;
    bpf_probe_read_user(&ssl_info, sizeof(ssl_info), ssl);

    struct BIO bio_r;
    bpf_probe_read_user(&bio_r, sizeof(bio_r), ssl_info.rbio);

    struct ssl_st_inner ssl_inner;
    bpf_probe_read_user(&ssl_inner, sizeof(ssl_inner), ssl_info.ssl);

#ifdef DEBUG
    bpf_printk("ssl=%ld, bio_r: %s %d %d %d %d, type: %d, version: %d", (u64)ssl, bio_r.cb_arg, bio_r.shutdown, bio_r.flags, bio_r.retry_reason, bio_r.num, ssl_inner.type, ssl_info.version);
#endif
    return bio_r.num;
}

static __inline int ssl_write_fd(void *ssl)
{
    struct ssl_st ssl_info;
    bpf_probe_read_user(&ssl_info, sizeof(ssl_info), ssl);

    struct BIO bio_w;
    bpf_probe_read_user(&bio_w, sizeof(bio_w), ssl_info.wbio);

#ifdef DEBUG
    bpf_printk("ssl=%ld, bio_w: %s %d %d %d %d", (u64)ssl, bio_w.cb_arg, bio_w.shutdown, bio_w.flags, bio_w.retry_reason, bio_w.num);
#endif
    return bio_w.num;
}

SEC("uprobe/libssl.so:SSL_read")
int BPF_UPROBE(uprobe_ssl_read, void *ssl, const void *buf, int num)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    int fd = ssl_read_fd(ssl);

    struct data_args_t read_args = {};
    // finding the file descriptor doesn't always work, we need to do ssl correlation in that case
    read_args.fd = (fd > 0) ? fd : (u64)ssl;
    read_args.buf = buf;

    bpf_map_update_elem(&active_read_ssl_args, &id, &read_args, BPF_ANY);

    u8 t = 1;
    bpf_map_update_elem(&active_accept_ssl, &id, &t, BPF_ANY);

    return 0;
}

SEC("uprobe/libssl.so:SSL_read_ex")
int BPF_UPROBE(uprobe_ssl_read_ex, void *ssl, const void *buf, int num, size_t *readbytes)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    int fd = ssl_read_fd(ssl);

    struct data_args_t read_args = {};
    read_args.fd = (fd > 0) ? fd : (u64)ssl;
    read_args.buf = buf;
    read_args.size = readbytes;

    bpf_map_update_elem(&active_read_ssl_args, &id, &read_args, BPF_ANY);

    u8 t = 1;
    bpf_map_update_elem(&active_accept_ssl, &id, &t, BPF_ANY);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_read")
int BPF_URETPROBE(uretprobe_ssl_read, size_t count)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

#ifdef DEBUG
    bpf_printk("Read ssl");
#endif
    if (((int)count) > 0)
    {

        struct data_args_t *args = bpf_map_lookup_elem(&active_read_ssl_args, &id);
        if (!args)
        {
            goto cleanup;
        }

        // load the active buffer
        const char *active_buf = args->buf;
        if (!active_buf)
        {
            bpf_printk("no active buffer");
            goto cleanup;
        }

        if ((int)count > 0)
        {
            _ringbuf_handler(kEventTypeSyscallReadAndInitEvent, id, args->fd, active_buf, count);
        }
    }
cleanup:
    bpf_map_delete_elem(&active_read_ssl_args, &id);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_read_ex")
int BPF_URETPROBE(uretprobe_ssl_read_ex, int ret)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

#ifdef DEBUG
    bpf_printk("Read ex SSL");
#endif

    if (ret)
    {
        struct data_args_t *args = bpf_map_lookup_elem(&active_read_ssl_args, &id);
        if (!args)
        {
            goto cleanup;
        }

        // load the active buffer
        const char *active_buf = args->buf;
        if (!active_buf)
        {
            bpf_printk("no active buffer");
            goto cleanup;
        }

        size_t count = 0;
        bpf_probe_read(&count, sizeof(size_t), (void *)args->size);

        if ((int)count > 0)
        {
            _ringbuf_handler(kEventTypeSyscallReadAndInitEvent, id, args->fd, active_buf, count);
        }
    }
cleanup:
    bpf_map_delete_elem(&active_read_ssl_args, &id);

    return 0;
}

SEC("uprobe/libssl.so:SSL_write")
int BPF_UPROBE(uprobe_ssl_write, void *ssl, const void *buf, int num)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    int fd = ssl_write_fd(ssl);

    struct data_args_t write_args = {};
    write_args.fd = (fd > 0) ? fd : (u64)ssl;
    write_args.buf = buf;
    write_args.size = NULL;

    bpf_map_update_elem(&active_write_ssl_args, &id, &write_args, BPF_ANY);

    return 0;
}

SEC("uprobe/libssl.so:SSL_write_ex")
int BPF_UPROBE(uprobe_ssl_write_ex, void *ssl, const void *buf, size_t num, size_t *written)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    int fd = ssl_write_fd(ssl);

    struct data_args_t write_args = {};
    write_args.fd = (fd > 0) ? fd : (u64)ssl;
    write_args.buf = buf;
    write_args.size = written;

    bpf_map_update_elem(&active_write_ssl_args, &id, &write_args, BPF_ANY);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write")
int BPF_URETPROBE(uretprobe_ssl_write, size_t count)
{
    struct syscall_write_event_t *e;
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

#ifdef DEBUG
    bpf_printk("Write SSL");
#endif

    if (((int)count) > 0)
    {
        struct data_args_t *args = bpf_map_lookup_elem(&active_write_ssl_args, &id);
        if (!args)
        {
            goto cleanup;
        }

        // load the active buffer
        const char *active_buf = args->buf;
        if (!active_buf)
        {
            bpf_printk("no active buffer");
            goto cleanup;
        }

        if ((int)count > 0)
        {
            _ringbuf_handler(kEventTypeSyscallWriteEvent, id, args->fd, active_buf, count);
        }
    }

cleanup:
    bpf_map_delete_elem(&active_write_ssl_args, &id);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write_ex")
int BPF_URETPROBE(uretprobe_ssl_write_ex, size_t ret)
{
    struct syscall_write_event_t *e;
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

#ifdef DEBUG
    bpf_printk("Write SSL ex");
#endif

    if (ret)
    {
        struct data_args_t *args = bpf_map_lookup_elem(&active_write_ssl_args, &id);
        if (!args)
        {
            goto cleanup;
        }

        // load the active buffer
        const char *active_buf = args->buf;
        if (!active_buf)
        {
            bpf_printk("no active buffer");
            goto cleanup;
        }

        size_t count = 0;
        bpf_probe_read(&count, sizeof(size_t), (void *)args->size);

        if ((int)count > 0)
        {
            _ringbuf_handler(kEventTypeSyscallWriteEvent, id, args->fd, active_buf, count);
        }
    }

cleanup:
    bpf_map_delete_elem(&active_write_ssl_args, &id);

    return 0;
}

SEC("uprobe/libssl.so:SSL_shutdown")
int BPF_UPROBE(uprobe_ssl_shutdown, void *ssl)
{
    struct syscall_write_event_t *e;
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    bpf_map_delete_elem(&active_accept_ssl, &id);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
    {
        bpf_printk("ssl close: couldn't allocate ring buffer request");
        return 0;
    }

    e->attr.event_type = kEventTypeSyscallCloseEvent;
    e->attr.fd = id;
    e->attr.msg_size_or_type = 0;
    e->attr.bytes = 0;
    e->attr.ts = 0;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("kprobe/__sys_recvfrom")
int BPF_KPROBE(kprobe_sys_recvfrom, int fd, void *ubuf, size_t size, unsigned int flags, struct sockaddr *addr, int *addr_len)
{
    struct syscall_write_event_t *e;
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    if (bpf_map_lookup_elem(&active_accept_ssl, &id))
    {
#ifdef DEBUG
        bpf_printk("SSL connection - ignore");
#endif
        return 0;
    }

    if (!bpf_map_lookup_elem(&active_fds, &fd))
    {
        // see if this was a cloned fd
        u32 *cloned_fd = bpf_map_lookup_elem(&fcntl_fd_to_fd, &fd);
        u8 active = 0;

        if (cloned_fd)
        {
            fd = *cloned_fd;
            active = (bpf_map_lookup_elem(&active_fds, &fd) != NULL);
        }

        if (!active)
        {
            u8 t = 1;
            bpf_map_update_elem(&active_fds, &fd, &t, BPF_ANY);
        }
    }

    // stash these function arguments so we can use them upon return
    struct data_args_t read_args = {};
    read_args.fd = fd;
    read_args.buf = (char *)ubuf;

    bpf_map_update_elem(&active_read_args, &id, &read_args, BPF_ANY);

    return 0;
}

SEC("kretprobe/__sys_recvfrom")
int BPF_KRETPROBE(kretprobe_sys_recvfrom, size_t count)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    if (((int)count) > 0)
    {
        struct syscall_write_event_t *e;
        struct data_args_t *args = bpf_map_lookup_elem(&active_read_args, &id);
        if (!args)
        {
            goto cleanup;
        }

        uint active_fd = args->fd;

        // check to see if this fd we are reading is actively tracked
        if (!bpf_map_lookup_elem(&active_fds, &active_fd))
        {
            goto cleanup;
        }

#ifdef DEBUG
        bpf_printk("active recvfrom fd=%d", active_fd);
#endif

        // load the active buffer
        const char *active_buf = args->buf;
        if (!active_buf)
        {
            bpf_printk("no active buffer");
            goto cleanup;
        }

        _ringbuf_handler(kEventTypeSyscallReadAndInitEvent, id, active_fd, active_buf, count);
    }

cleanup:
    bpf_map_delete_elem(&active_read_args, &id);

    return 0;
}

SEC("kprobe/__sys_sendto")
int BPF_KPROBE(kprobe_sys_sendto, int fd, void *buff, size_t len, unsigned int flags, struct sockaddr *addr, int addr_len)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    if (bpf_map_lookup_elem(&active_accept_ssl, &id))
    {
#ifdef DEBUG
        bpf_printk("SSL connection - ignore");
#endif
        return 0;
    }

#ifdef DEBUG
    bpf_printk("Send to fd=%d, pid=%d", fd, id >> 32);
#endif

    if (!bpf_map_lookup_elem(&active_fds, &fd))
    {
#ifdef DEBUG
        bpf_printk("Not active");
#endif

        u32 *cloned_fd = bpf_map_lookup_elem(&fcntl_fd_to_fd, &fd);
        if (cloned_fd)
        {
#ifdef DEBUG
            bpf_printk("cloned_fd %d", *cloned_fd);
#endif

            if (bpf_map_lookup_elem(&active_fds, cloned_fd))
            {
#ifdef DEBUG
                bpf_printk("Found mapping %d -> %d", fd, *cloned_fd);
#endif
                fd = *cloned_fd;
            }
            else
            {
                return 0;
            }
        }
        else
        {
#ifdef DEBUG
            bpf_printk("No clone fd");
#endif
            // Bail early if we aren't tracking this fd.
            return 0;
        }
    }

#ifdef DEBUG
    bpf_printk("1: Send to fd=%d, pid=%d", fd, id >> 32);
#endif

    return _ringbuf_handler(kEventTypeSyscallWriteEvent, id, fd, buff, len);
}

SEC("kprobe/do_fcntl")
int BPF_KPROBE(kprobe_sys_fcntl, int fd, unsigned int cmd, unsigned long arg, struct file *filp)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    bpf_map_update_elem(&fcntl_id_to_fd, &id, &fd, BPF_ANY);

#ifdef DEBUG
    bpf_printk("fcntl stored fd=%d for id=%ld", fd, id);
#endif

    u32 *fd_from = bpf_map_lookup_elem(&fcntl_id_to_fd, &id);

    if (!fd_from)
    {
#ifdef DEBUG
        bpf_printk("fcntl not found id=%ld", id);
#endif
        // Bail early if we aren't tracking this fd.
        return 0;
    }

    return 0;
}

SEC("kretprobe/do_fcntl")
int BPF_KRETPROBE(kretprobe_sys_fcntl, u32 fd)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id))
    {
        return 0;
    }

    u32 *fd_to = bpf_map_lookup_elem(&fcntl_id_to_fd, &id);

    if (!fd_to)
    {
#ifdef DEBUG
        bpf_printk("fcntl not found id=%ld", id);
#endif
        // Bail early if we aren't tracking this fd.
        return 0;
    }

    bpf_map_delete_elem(&fcntl_id_to_fd, &id);

#ifdef DEBUG
    bpf_printk("fcntl from=%d to %d", fd, *fd_to);
#endif

    bpf_map_update_elem(&fcntl_fd_to_fd, &fd, fd_to, BPF_ANY);
    return 0;
}
