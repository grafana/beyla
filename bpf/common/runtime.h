#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <maps/active_unix_socks.h>

#include <pid/pid_helpers.h>

static __always_inline u64 extra_runtime_id() {
    const u64 id = bpf_get_current_pid_tgid();
    const u32 *inode_num = (const u32 *)bpf_map_lookup_elem(&active_unix_socks, &id);

    return inode_num ? (u64)(*inode_num) : 0;
}
