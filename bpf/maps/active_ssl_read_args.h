#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/ssl_args.h>
#include <common/pin_internal.h>

// TODO: we should be able to make this into a single map. It's not a big deal because they are really only
// tracking the parameters of SSL_read and SSL_write, so their memory consumption is minimal. If we can be
// 100% certain that SSL_read will never do an SSL_write, then these can be a single map.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __type(key, u64);
    __type(value, ssl_args_t);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} active_ssl_read_args SEC(".maps");
