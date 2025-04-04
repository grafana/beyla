#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>

// A map of sockets which we track with sock_ops. The sock_msg
// program subscribes to this map and runs for each new socket
// activity
// The map size must be max u16 to avoid accidentally losing
// the socket information
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(connection_info_t));
    __uint(value_size, sizeof(uint32_t));
} sock_dir SEC(".maps");
