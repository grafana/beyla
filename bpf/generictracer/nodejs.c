//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/ringbuf.h>

#include <generictracer/maps/async_id_to_fd.h>
#include <generictracer/maps/node_client_requests.h>
#include <generictracer/maps/node_fds.h>
#include <generictracer/types/async_id_to_fd_key.h>
#include <generictracer/types/node_client_request_key.h>
#include <generictracer/types/node_provider_type.h>

#include <logger/bpf_dbg.h>

#include <maps/active_nodejs_ids.h>
#include <maps/fd_to_connection.h>

#include <pid/pid.h>

enum { k_invalid_request_id = 0 };

static __always_inline node_provider_type wrap_provider(const void *wrap) {
    node_provider_type provider;
    bpf_probe_read_user(&provider, sizeof(provider), wrap + 0x30);

    return provider;
}

static __always_inline u64 read_u64(const void *wrap, u32 offset) {
    u64 value;
    bpf_probe_read_user(&value, sizeof(value), wrap + offset);

    return value;
}

static __always_inline u64 wrap_async_id(const void *wrap) {
    return read_u64(wrap, 0x38);
}

static __always_inline u64 wrap_trigger_async_id(const void *wrap) {
    return read_u64(wrap, 0x40);
}

static __always_inline void *stream_wrap_stream(const void *wrap) {
    void *stream;
    bpf_probe_read_user(&stream, sizeof(stream), wrap + 0xb0);

    return stream;
}

static __always_inline s32 stream_fd(const void *stream) {
    s32 fd;

    bpf_probe_read_user(&fd, sizeof(fd), stream + 0xb8);

    return fd;
}

static __always_inline s32 stream_wrap_fd(const void *wrap) {
    return stream_fd(stream_wrap_stream(wrap));
}

static __always_inline u64 get_active_parent_request(u64 pid_tgid) {
    const u64 *active_request_id = bpf_map_lookup_elem(&active_nodejs_ids, &pid_tgid);

    return active_request_id ? *active_request_id : k_invalid_request_id;
}

static __always_inline void set_active_parent_request(u64 request_id, u64 pid_tgid) {
    bpf_map_update_elem(&active_nodejs_ids, &pid_tgid, &request_id, BPF_ANY);
}

static __always_inline void
set_parent_request(u64 client_request_id, u64 parent_request_id, u64 pid_tgid) {
    const node_client_request_key key = {.pid_tgid = pid_tgid,
                                         .client_request_id = client_request_id};

    bpf_map_update_elem(&node_client_requests, &key, &parent_request_id, BPF_ANY);
}

static __always_inline u64 get_parent_request(u64 client_request_id, u64 pid_tgid) {
    const node_client_request_key key = {.pid_tgid = pid_tgid,
                                         .client_request_id = client_request_id};

    const u64 *parent_request_id = bpf_map_lookup_elem(&node_client_requests, &key);

    return parent_request_id ? *parent_request_id : k_invalid_request_id;
}

static __always_inline void set_active_fd(s32 fd, u64 pid_tgid) {
    bpf_map_update_elem(&node_fds, &pid_tgid, &fd, BPF_ANY);
}

static __always_inline s32 get_active_fd(u64 pid_tgid) {
    const u32 *fd = bpf_map_lookup_elem(&node_fds, &pid_tgid);

    return fd ? *fd : -1;
}

static __always_inline void set_async_id_fd(u64 async_id, s32 fd, u64 pid_tgid) {
    const async_id_to_fd_key key = {.pid_tgid = pid_tgid, .async_id = async_id};

    bpf_map_update_elem(&async_id_to_fd, &key, &fd, BPF_ANY);
}

static __always_inline s32 get_async_id_fd(u64 async_id, u64 pid_tgid) {
    const async_id_to_fd_key key = {.pid_tgid = pid_tgid, .async_id = async_id};

    const s32 *fd = bpf_map_lookup_elem(&async_id_to_fd, &key);

    return fd ? *fd : -1;
}

static __always_inline void async_reset_httpincomingmessage(const void *wrap, u64 pid_tgid) {
    // (2) we get the accepted fd and associated with this incoming request -
    // this fd will be used as the parent request id for the client requests
    // originating from this incoming request
    const s32 fd = get_active_fd(pid_tgid);
    const u64 async_id = wrap_async_id(wrap);

    bpf_dbg_printk("NODEE === async_reset_httpincomingmessage wrap=%llx, id=%llu, fd=%d\n",
                   wrap,
                   async_id,
                   fd);

    set_async_id_fd(async_id, fd, pid_tgid);
}

static __always_inline void async_reset_httpclientrequest(const void *wrap, u64 pid_tgid) {
    const u64 async_id = wrap_async_id(wrap);

    bpf_dbg_printk("NODEE === uprobe AsyncReset id=%llu wrap=%llx ===", async_id, wrap);

    const u64 parent_request_id = get_active_parent_request(pid_tgid);

    if (parent_request_id == k_invalid_request_id) {
        bpf_dbg_printk("NODEE found orphan client request (%llu), ignoring...", async_id);
        return;
    }

    bpf_dbg_printk("NODEE new client request started wrap = %llx, id = %llu, parent = %llu",
                   wrap,
                   async_id,
                   parent_request_id);

    // (4a) associated the parent_request_id / incoming fd to this client
    // request
    set_parent_request(async_id, parent_request_id, pid_tgid);
}

static __always_inline void async_reset_tcpwrap(const void *wrap, u64 pid_tgid) {
    const u64 async_id = wrap_async_id(wrap);
    const u64 trigger_async_id = wrap_trigger_async_id(wrap);

    // (4) node is now creating the client request connection we associate the
    // parent connection id (fd) to this new client connection

    // when the trigger_async_id is > 0, that means this wrap object is being
    // directly created as a result of the handle_incoming_request callback -
    // i.e. it's either the first client call or it's running as part of the
    // same async context - otherwise, if this is starting after a previous
    // async operation has completed (i.e. a previous client call has
    // finished), we grab the value that was propagated via
    // handle_client_request
    const s32 fd = trigger_async_id > 0 ? get_async_id_fd(trigger_async_id, pid_tgid)
                                        : get_active_parent_request(pid_tgid);

    bpf_dbg_printk("NODEE async_reset_tcpwrap wrap=%llx async_id=%llu trigger=%llu fd=%d",
                   wrap,
                   async_id,
                   trigger_async_id,
                   fd);

    set_async_id_fd(async_id, fd, pid_tgid);
}

SEC("uprobe/node:AsyncReset")
int beyla_async_reset(struct pt_regs *ctx) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!valid_pid(pid_tgid)) {
        return 0;
    }

    const void *wrap = (const void *)PT_REGS_PARM1(ctx);
    const node_provider_type provider = wrap_provider(wrap);

    [[maybe_unused]] const u64 async_id = wrap_async_id(wrap);
    [[maybe_unused]] const u64 trigger = wrap_trigger_async_id(wrap);

    bpf_dbg_printk("NODEE AsyncReset wrap=%llx, provider=%u, id=%llu, trigger=%llu",
                   wrap,
                   provider,
                   async_id,
                   trigger);

    switch (provider) {
    case NODE_PROVIDER_HTTPINCOMINGMESSAGE:
        async_reset_httpincomingmessage(wrap, pid_tgid);
        break;
    case NODE_PROVIDER_HTTPCLIENTREQUEST:
        async_reset_httpclientrequest(wrap, pid_tgid);
        break;
    case NODE_PROVIDER_TCPWRAP:
        async_reset_tcpwrap(wrap, pid_tgid);
        break;
    default:
        break;
    }

    return 0;
}

static __always_inline void handle_incoming_request(u64 async_id, u64 pid_tgid) {
    const u64 parent_request_id = get_async_id_fd(async_id, pid_tgid);

    bpf_dbg_printk(
        "NODEE new request received async_id=%llu, fd=%llu", async_id, parent_request_id);

    // (3) node is done processing the incoming request and will trigger the
    // first client request - so we use the incoming request fd as the parent
    // id
    set_active_parent_request(parent_request_id, pid_tgid);
}

static __always_inline void handle_client_request(u64 async_id, u64 pid_tgid) {
    const u64 parent_request_id = get_parent_request(async_id, pid_tgid);
    bpf_dbg_printk(
        "NODEE client request finished async_id=%llu, parent = %llu", async_id, parent_request_id);

    // (2) reset the active parent request to this client request's parent request
    // so that the next client request in the chain can be linked to it
    set_active_parent_request(parent_request_id, pid_tgid);
}

static __always_inline void handle_tcp_connect_wrap(u64 trigger_async_id, u64 pid_tgid) {
    const s32 fd = get_async_id_fd(trigger_async_id, pid_tgid);

    bpf_dbg_printk("NODEE === handle_tcp_connect_wrap trigger=%llu fd = %d", trigger_async_id, fd);

    // (5) the client connection is about to start - TCPCONNECTWRAP is always
    // triggered by a TCPWRAP, so we simply grab the fd set up by it during
    // step (4) and that's the fd of the parent call that will be used to look
    // up the associated trace in find_nodejs_parent_trace()
    set_active_parent_request(fd, pid_tgid);
}

SEC("uprobe/node:MakeCallback")
int beyla_make_callback(struct pt_regs *ctx) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!valid_pid(pid_tgid)) {
        return 0;
    }

    const void *wrap = (const void *)PT_REGS_PARM1(ctx);
    const node_provider_type provider = wrap_provider(wrap);
    const u64 async_id = wrap_async_id(wrap);
    const u64 trigger = wrap_trigger_async_id(wrap);

    bpf_dbg_printk("NODEE === uprobe MakeCallback wrap=%llx, provider=%u, id=%llu, trigger=%llu",
                   wrap,
                   provider,
                   async_id,
                   trigger);

    switch (provider) {
    case NODE_PROVIDER_HTTPINCOMINGMESSAGE:
        handle_incoming_request(async_id, pid_tgid);
        break;
    case NODE_PROVIDER_HTTPCLIENTREQUEST:
        handle_client_request(async_id, pid_tgid);
        break;
    case NODE_PROVIDER_TCPCONNECTWRAP:
        handle_tcp_connect_wrap(trigger, pid_tgid);
        break;
    default:
        break;
    }

    return 0;
}

SEC("uprobe/node:OnConnection")
int beyla_on_connection(struct pt_regs *ctx) {
    const u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!valid_pid(pid_tgid)) {
        return 0;
    }

    const void *handle = (const void *)PT_REGS_PARM1(ctx);

    s32 accepted_fd;
    bpf_core_read_user(&accepted_fd, sizeof(accepted_fd), handle + 0xec);

    bpf_dbg_printk("NODEE === uprobe OnConnection fd = %d", accepted_fd);

    // (1) new incoming connection, we store the accepted fd
    set_active_fd(accepted_fd, pid_tgid);

    return 0;
}
