#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>

#include <logger/bpf_dbg.h>

#include <maps/active_ssl_connections.h>
#include <maps/active_ssl_read_args.h>
#include <maps/active_ssl_write_args.h>
#include <maps/ssl_to_conn.h>

static __always_inline void set_active_ssl_connection(pid_connection_info_t *conn, void *ssl) {

    bpf_dbg_printk("Correlating SSL %llx to connection", ssl);
    dbg_print_http_connection_info(&conn->conn);

    bpf_map_update_elem(&active_ssl_connections, conn, &ssl, BPF_ANY);
    bpf_map_update_elem(&ssl_to_conn, &ssl, conn, BPF_ANY);
}

static __always_inline void *is_ssl_connection(u64 id, pid_connection_info_t *conn) {
    void *ssl = 0;
    // Checks if it's sandwitched between active SSL handshake, read or write uprobe/uretprobe
    ssl_args_t *ssl_args = bpf_map_lookup_elem(&active_ssl_read_args, &id);

    if (!ssl_args) {
        ssl_args = bpf_map_lookup_elem(&active_ssl_write_args, &id);
    }

    if (ssl_args) {
        ssl = (void *)ssl_args->ssl;
    }

    if (!ssl) {
        return bpf_map_lookup_elem(&active_ssl_connections, conn);
    }

    set_active_ssl_connection(conn, ssl);

    return ssl;
}
