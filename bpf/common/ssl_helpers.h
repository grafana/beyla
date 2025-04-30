#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/protocol_defs.h>

#include <logger/bpf_dbg.h>

#include <maps/active_ssl_connections.h>
#include <maps/active_ssl_read_args.h>
#include <maps/active_ssl_write_args.h>
#include <maps/ssl_to_conn.h>

static __always_inline void *is_ssl_connection(u64 id, pid_connection_info_t *conn, u8 direction) {
    void *ssl = 0;
    ssl_args_t *ssl_args = 0;

    ssl = bpf_map_lookup_elem(&active_ssl_connections, conn);
    if (ssl) {
        return ssl;
    }

    // Checks if it's sandwitched between read or write uprobe/uretprobe
    if (direction == TCP_RECV) {
        ssl_args = bpf_map_lookup_elem(&active_ssl_read_args, &id);
        if (ssl_args) {
        } else {
            ssl_args = bpf_map_lookup_elem(&active_ssl_write_args, &id);
        }
    } else if (direction == TCP_SEND) {
        ssl_args = bpf_map_lookup_elem(&active_ssl_write_args, &id);
        if (ssl_args) {
        } else {
            ssl_args = bpf_map_lookup_elem(&active_ssl_read_args, &id);
        }
    } else {
        bpf_dbg_printk("unknown ssl connection direction, this is a bug");
    }

    if (ssl_args) {
        ssl = (void *)ssl_args->ssl;
    }

    return ssl;
}
