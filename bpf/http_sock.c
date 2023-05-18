#include "vmlinux.h"
#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "bpf_dbg.h"
#include "pid.h"
#include "sockaddr.h"
#include "ringbuf.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, accept_args_t);
} active_accept_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, http_connection_info_t);
    __type(value, u64); // PID_TID group
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} filtered_connections SEC(".maps");

SEC("kretprobe/sock_alloc")
int BPF_KRETPROBE(kretprobe_sock_alloc, struct socket *sock) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== sock alloc %llx ===", id);

    u64 addr = (u64)sock;

    accept_args_t args = {};

    args.addr = addr;
    args.accept_time = bpf_ktime_get_ns();

    // The socket->sock is not valid until accept finishes, therefore
    // we don't extract ->sock here, we remember the address of socket
    // and parse in sys_accept
    bpf_map_update_elem(&active_accept_args, &id, &args, BPF_ANY);

    return 0;
}

// We tap into __sys_accept4 because it handles both sys_accept and sys_accept4.
// We don't care about the accept entry arguments, since we get only peer information
// we don't have the full picture for the socket.
// 
// Note: A current limitation is that likely we won't capture the first accept request. The
// process may have already reached accept, before the instrumenter has launched.
SEC("kretprobe/sys_accept4")
int BPF_KRETPROBE(kretprobe_sys_accept4, uint fd)
{
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== accept 4 ret id=%d ===", id);

    // The file descriptor is the value returned from the accept4 syscall.
    // If we got a negative file descriptor we don't have a connection
    if ((int)fd < 0) {
        goto cleanup;
    }

    accept_args_t *args = bpf_map_lookup_elem(&active_accept_args, &id);
    if (!args) {
        bpf_dbg_printk("No sock info %d", id);
        goto cleanup;
    }

    http_connection_info_t info = {};

    parse_sock_info(args, &info);
    sort_connection_info(&info);
    dbg_print_http_connection_info(&info);

    bpf_map_update_elem(&filtered_connections, &info, &id, BPF_ANY); // On purpose BPF_ANY, we want to overwrite stale

cleanup:
    bpf_map_delete_elem(&active_accept_args, &id);
    return 0;
}

