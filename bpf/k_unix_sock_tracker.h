#ifndef _K_UNIX_SOCK_TRACKER
#define _K_UNIX_SOCK_TRACKER

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include "map_sizing.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);   // the pid_tid
    __type(value, u32); // the last seen ino
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} active_unix_socks SEC(".maps");

#endif