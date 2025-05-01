#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/protocol_defs.h>
#include <common/sockaddr.h>

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

static __always_inline void *unconnected_ssl_from_args(u64 id, u8 direction) {
    ssl_args_t *ssl_args = 0;

    // Checks if it's sandwitched between read or write uprobe/uretprobe
    if (direction == TCP_RECV) {
        ssl_args = bpf_map_lookup_elem(&active_ssl_read_args, &id);
    } else if (direction == TCP_SEND) {
        ssl_args = bpf_map_lookup_elem(&active_ssl_write_args, &id);
    } else {
        bpf_dbg_printk("unknown ssl connection direction, this is a bug");
    }

    if (ssl_args && !ssl_args_connected(ssl_args)) {
        set_ssl_args_connected(ssl_args);
        return (void *)ssl_args->ssl;
    }

    return 0;
}

static __always_inline void connect_ssl_to_sock(u64 id, struct sock *sock, u8 direction) {
    void *ssl = unconnected_ssl_from_args(id, direction);
    if (!ssl) {
        return;
    }
    pid_connection_info_t p_conn = {0};
    p_conn.pid = pid_from_pid_tgid(id);
    bool success = parse_sock_info(sock, &p_conn.conn);
    if (success) {
        sort_connection_info(&p_conn.conn);
        set_active_ssl_connection(&p_conn, ssl);
    }
}

static __always_inline void
connect_ssl_to_connection(u64 id, pid_connection_info_t *conn, u8 direction) {
    void *ssl = unconnected_ssl_from_args(id, direction);
    if (!ssl) {
        return;
    }
    set_active_ssl_connection(conn, ssl);
}

static __always_inline void *is_ssl_connection(pid_connection_info_t *conn) {
    return bpf_map_lookup_elem(&active_ssl_connections, conn);
}
