#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <maps/active_unix_socks.h>
#include <maps/active_nodejs_ids.h>
#include <maps/nodejs_parent_map.h>

#include <pid/pid.h>

static __always_inline u64 extra_runtime_id() {
    u64 id = bpf_get_current_pid_tgid();

    u64 *active_node_id = (u64 *)bpf_map_lookup_elem(&active_nodejs_ids, &id);
    if (active_node_id) {
        return *active_node_id;
    }

    u32 *inode_num = (u32 *)bpf_map_lookup_elem(&active_unix_socks, &id);
    if (inode_num) {
        return (u64)(*inode_num);
    }

    return 0;
}

static __always_inline u64 parent_runtime_id(u64 runtime_id) {
    u64 *parent_id = (u64 *)bpf_map_lookup_elem(&nodejs_parent_map, &runtime_id);
    if (parent_id) {
        return *parent_id;
    }

    return 0;
}
