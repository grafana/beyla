//go:build beyla_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/fd_info.h>
#include <common/connection_info.h>

#include <logger/bpf_dbg.h>

#include <maps/nginx_upstream.h>

#include <pid/pid.h>

volatile const s32 ngx_http_request_s_conn = 0x8;
volatile const s32 ngx_http_request_s_upstream = 0x48;
volatile const s32 ngx_http_upstream_s_conn = 0x10;
volatile const s32 ngx_connection_s_fd = 0x18;
volatile const s32 ngx_http_rev_s_conn = 0x8;
volatile const s32 ngx_connection_s_sockaddr = 0x68;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // the pid_tid
    __type(value, u64); // the req ptr
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} upstream_init_args SEC(".maps");

SEC("uprobe/nginx:ngx_http_upstream_init")
int beyla_ngx_http_upstream_init(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    void *req = (void *)PT_REGS_PARM1(ctx);
    u64 req_val = (u64)req;

    bpf_map_update_elem(&upstream_init_args, &id, &req_val, BPF_ANY);

    return 0;
}

static __always_inline void get_sock_info(void *conn_ptr, connection_info_part_t *part) {
    if (conn_ptr) {
        void *sockaddr_ptr = 0;
        bpf_probe_read(&sockaddr_ptr, sizeof(void *), conn_ptr + ngx_connection_s_sockaddr);

        bpf_dbg_printk("sock_addr %llx", sockaddr_ptr);
        if (sockaddr_ptr) {
            parse_sockaddr_info((struct sockaddr *)sockaddr_ptr, part);
            bpf_dbg_printk("connection port %d", part->port);
        }
    }
}

SEC("uprobe/nginx:ngx_event_connect_peer_ret")
int beyla_ngx_event_connect_peer_ret(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    u64 *req_val = bpf_map_lookup_elem(&upstream_init_args, &id);

    bpf_dbg_printk("=(o|o)= uretprobe ngx_event_connect_peer id=%d, req_val %llx", id, req_val);

    if (!req_val) {
        return 0;
    }

    void *req = (void *)(*req_val);
    void *conn_ptr = 0;
    bpf_probe_read(&conn_ptr, sizeof(void *), req + ngx_http_request_s_conn);

    void *up_ptr = 0;
    bpf_probe_read(&up_ptr, sizeof(void *), req + ngx_http_request_s_upstream);

    connection_info_part_t part = {0};
    get_sock_info(conn_ptr, &part);

    void *peer_conn = 0;
    bpf_probe_read(&peer_conn, sizeof(void *), up_ptr + ngx_http_upstream_s_conn);

    int fd = 0;
    bpf_probe_read(&fd, sizeof(int), peer_conn + ngx_connection_s_fd);
    bpf_dbg_printk("= PEER conn %llx, fd = %d =", peer_conn, fd);

    if (fd) {
        fd_info_t fdinfo = {};
        fd_info(&fdinfo, fd, FD_CLIENT);
        bpf_map_update_elem(&nginx_upstream, &fdinfo, &part, BPF_ANY);
    }

    return 0;
}