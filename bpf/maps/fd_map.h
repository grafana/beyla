#pragma once

#include <bpfcore/utils.h>

#include <common/connection_info.h>
#include <common/fd_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_part_t); // key: the connection info
    __type(value, fd_info_t);            // value: file descriptor with pid/tid information
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} fd_map SEC(".maps");

static __always_inline void get_ephemeral_info(connection_info_part_t *part,
                                               connection_info_t *unordered_conn) {
    __builtin_memcpy(part->addr, unordered_conn->s_addr, IP_V6_ADDR_LEN);
    part->port = unordered_conn->s_port;
}

static __always_inline void get_ephemeral_accept_info(connection_info_part_t *part,
                                                      connection_info_t *unordered_conn) {
    __builtin_memcpy(part->addr, unordered_conn->d_addr, IP_V6_ADDR_LEN);
    part->port = unordered_conn->d_port;
}

static __always_inline void
store_connect_fd_info(u32 pid, int fd, connection_info_t *unordered_conn) {
    fd_info_t fdinfo = {};
    fd_info(&fdinfo, fd, FD_CLIENT);
    connection_info_part_t part = {};
    get_ephemeral_info(&part, unordered_conn);
    part.type = FD_CLIENT;
    part.pid = pid;
    bpf_dbg_printk("storing client info for fd=%d, type=%d", fd, part.type);
    dbg_print_http_connection_info_part(&part);
    bpf_map_update_elem(&fd_map, &part, &fdinfo, BPF_ANY);
}

static __always_inline void
store_accept_fd_info(u32 pid, int fd, connection_info_t *unordered_conn) {
    fd_info_t fdinfo = {};
    fd_info(&fdinfo, fd, FD_SERVER);
    connection_info_part_t part = {};
    get_ephemeral_accept_info(&part, unordered_conn);
    part.type = FD_SERVER;
    part.pid = pid;
    bpf_dbg_printk("storing server info for fd=%d, type=%d", fd, part.type);
    dbg_print_http_connection_info_part(&part);
    bpf_map_update_elem(&fd_map, &part, &fdinfo, BPF_ANY);
}

static __always_inline fd_info_t *fd_info_for_conn(connection_info_part_t *part) {
    bpf_dbg_printk("looking up fd info for");
    dbg_print_http_connection_info_part(part);
    return bpf_map_lookup_elem(&fd_map, part);
}
