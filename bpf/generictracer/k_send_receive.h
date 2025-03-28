#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <generictracer/k_tracer_defs.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);
    __type(value, recv_args_t);
} active_recv_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);           // pid_tid
    __type(value, send_args_t); // size to be sent
} active_send_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __type(key, u64);           // *sock
    __type(value, send_args_t); // size to be sent
} active_send_sock_args SEC(".maps");

static __always_inline void ensure_sent_event(u64 id, u64 *sock_p) {
    if (high_request_volume) {
        return;
    }
    send_args_t *s_args = (send_args_t *)bpf_map_lookup_elem(&active_send_args, &id);
    if (s_args) {
        bpf_dbg_printk("Checking if we need to finish the request per thread id");
        finish_possible_delayed_http_request(&s_args->p_conn);
    } // see if we match on another thread, but same sock *
    s_args = (send_args_t *)bpf_map_lookup_elem(&active_send_sock_args, sock_p);
    if (s_args) {
        bpf_dbg_printk("Checking if we need to finish the request per socket");
        finish_possible_delayed_http_request(&s_args->p_conn);
    }
}
