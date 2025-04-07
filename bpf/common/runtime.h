#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/float64.h>

#include <logger/bpf_dbg.h>

#include <maps/active_unix_socks.h>
#include <maps/active_nodejs_ids.h>
#include <maps/nodejs_parent_map.h>

#include <pid/pid_helpers.h>

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
    u64 lookup_id = runtime_id;
    bpf_dbg_printk("parent lookup id %llx", lookup_id);
    u64 *parent_id = (u64 *)bpf_map_lookup_elem(&nodejs_parent_map, &lookup_id);
    if (parent_id) {
        return *parent_id;
    }

    // When NodeJS uses await, sometimes the JavaScript interpreted code, which
    // we cannot instrument will bump the asyncID. Because of this, we will not
    // be able to find out asyncID call chain for context propagation. This code
    // tries to look for close enough asyncIDs that will allow us to still
    // find the chain.
    for (u32 sub = 0; sub < 5; sub++) {
        // lookup_id (as double) - 1 (as double)
        lookup_id = sub_float64(lookup_id, 0x3ff0000000000000, 0);

        if (lookup_id == -1 || lookup_id == 0) {
            return 0;
        }

        bpf_dbg_printk("looking up id %llx", lookup_id);
        u64 *parent_id = (u64 *)bpf_map_lookup_elem(&nodejs_parent_map, &lookup_id);
        if (parent_id) {
            return *parent_id;
        }
    }

    return 0;
}
