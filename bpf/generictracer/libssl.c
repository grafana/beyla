//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/http_types.h>
#include <common/sockaddr.h>
#include <common/tcp_info.h>

#include <generictracer/ssl_defs.h>

#include <logger/bpf_dbg.h>

#include <maps/active_ssl_read_args.h>
#include <maps/active_ssl_write_args.h>

#include <pid/pid.h>

// SSL read and read_ex are more less the same, but some frameworks use one or the other.
// SSL_read_ex sets an argument pointer with the number of bytes read, while SSL_read returns
// the number of bytes read.
SEC("uprobe/libssl.so:SSL_read")
int BPF_UPROBE(beyla_uprobe_ssl_read, void *ssl, const void *buf, int num) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe SSL_read id=%d ssl=%llx ===", id, ssl);

    ssl_pid_connection_info_t *s_conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
    if (s_conn) {
        finish_possible_delayed_tls_http_request(&s_conn->p_conn, ssl);
    }

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.len_ptr = 0;
    args.flags = 0;

    bpf_map_update_elem(&active_ssl_read_args, &id, &args, BPF_ANY);
    bpf_map_update_elem(&ssl_to_pid_tid,
                        &args.ssl,
                        &id,
                        BPF_NOEXIST); // we must not overwrite here, remember the original thread

    return 0;
}

SEC("uretprobe/libssl.so:SSL_read")
int BPF_URETPROBE(beyla_uretprobe_ssl_read, int ret) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe SSL_read id=%d ===", id);

    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_read_args, &id);

    bpf_map_delete_elem(&active_ssl_read_args, &id);

    // must be last in the function, doesn't return
    handle_ssl_buf(ctx, id, args, ret, TCP_RECV);
    return 0;
}

SEC("uprobe/libssl.so:SSL_read_ex")
int BPF_UPROBE(beyla_uprobe_ssl_read_ex,
               void *ssl,
               const void *buf,
               int num,
               size_t *readbytes) { //NOLINT(readability-non-const-parameter)
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_read_ex id=%d ssl=%llx ===", id, ssl);

    ssl_pid_connection_info_t *s_conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
    if (s_conn) {
        finish_possible_delayed_tls_http_request(&s_conn->p_conn, ssl);
    }

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.len_ptr = (u64)readbytes;
    args.flags = 0;

    bpf_map_update_elem(&active_ssl_read_args, &id, &args, BPF_ANY);
    bpf_map_update_elem(&ssl_to_pid_tid,
                        &args.ssl,
                        &id,
                        BPF_NOEXIST); // we must not overwrite here, remember the original thread

    return 0;
}

SEC("uretprobe/libssl.so:SSL_read_ex")
int BPF_URETPROBE(beyla_uretprobe_ssl_read_ex, int ret) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe SSL_read_ex id=%d ===", id);

    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_read_args, &id);

    if (ret != 1 || !args || !args->len_ptr) {
        bpf_map_delete_elem(&active_ssl_read_args, &id);
        return 0;
    }

    size_t read_len = 0;
    bpf_probe_read(&read_len, sizeof(read_len), (void *)args->len_ptr);

    bpf_map_delete_elem(&active_ssl_read_args, &id);
    // must be last in the function, doesn't return
    handle_ssl_buf(ctx, id, args, read_len, TCP_RECV);
    return 0;
}

// SSL write and write_ex are more less the same, but some frameworks use one or the other.
// SSL_write_ex sets an argument pointer with the number of bytes written, while SSL_write returns
// the number of bytes written.
SEC("uprobe/libssl.so:SSL_write")
int BPF_UPROBE(beyla_uprobe_ssl_write, void *ssl, const void *buf, int num) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe SSL_write id=%d ssl=%llx ===", id, ssl);

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.len_ptr = num;
    args.flags = 0;

    bpf_map_update_elem(&active_ssl_write_args, &id, &args, BPF_ANY);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write")
int BPF_URETPROBE(beyla_uretprobe_ssl_write, int ret) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_write_args, &id);

    bpf_dbg_printk("=== uretprobe SSL_write id=%d args %llx ===", id, args);

    if (args) {
        ssl_args_t saved = {};
        __builtin_memcpy(&saved, args, sizeof(ssl_args_t));
        bpf_map_delete_elem(&active_ssl_write_args, &id);
        // must be last in the function, doesn't return
        handle_ssl_buf(ctx, id, &saved, saved.len_ptr, TCP_SEND);
    }

    return 0;
}

SEC("uprobe/libssl.so:SSL_write_ex")
int BPF_UPROBE(beyla_uprobe_ssl_write_ex, void *ssl, const void *buf, int num, size_t *written) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_write_ex id=%d ssl=%llx ===", id, ssl);

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.len_ptr = num;
    args.flags = 0;

    bpf_map_update_elem(&active_ssl_write_args, &id, &args, BPF_ANY);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write_ex")
int BPF_URETPROBE(beyla_uretprobe_ssl_write_ex, int ret) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_write_args, &id);

    bpf_dbg_printk("=== uretprobe SSL_write_ex id=%d args %llx ===", id, args);

    if (args) {
        ssl_args_t saved = {};
        __builtin_memcpy(&saved, args, sizeof(ssl_args_t));
        bpf_map_delete_elem(&active_ssl_write_args, &id);
        // must be last in the function, doesn't return
        handle_ssl_buf(ctx, id, &saved, saved.len_ptr, TCP_SEND);
    }

    return 0;
}

SEC("uprobe/libssl.so:SSL_shutdown")
int BPF_UPROBE(beyla_uprobe_ssl_shutdown, void *s) {
    u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_shutdown id=%d ssl=%llx ===", id, s);

    ssl_pid_connection_info_t *s_conn = bpf_map_lookup_elem(&ssl_to_conn, &s);
    if (s_conn) {
        finish_possible_delayed_tls_http_request(&s_conn->p_conn, s);
        bpf_map_delete_elem(&active_ssl_connections, &s_conn->p_conn);
    }

    bpf_map_delete_elem(&ssl_to_conn, &s);
    bpf_map_delete_elem(&ssl_to_pid_tid, &s);

    bpf_map_delete_elem(&pid_tid_to_conn, &id);

    return 0;
}
