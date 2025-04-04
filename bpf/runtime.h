#ifndef RUNTIME_SUPPORT_H
#define RUNTIME_SUPPORT_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "pid_types.h"
#include "nodejs.h"
#include "k_unix_sock_tracker.h"
#include "float64.h"

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

static __always_inline u32 extract_node_js_id(u64 runtime_id) {
    // Shift the runtime_id 40 bits to the right to isolate the uppermost 3 bytes
    return (u32)(runtime_id >> 44);
}

static __always_inline u64 parent_runtime_id(u64 runtime_id) {
    u64 lookup_id = runtime_id;
    bpf_printk("parent lookup id %llx", lookup_id);
    u64 *parent_id = (u64 *)bpf_map_lookup_elem(&nodejs_parent_map, &lookup_id);
    if (parent_id) {
        return *parent_id;
    }
    for (u32 sub = 0; sub < 5; sub++) {
        // lookup_id (as double) - 1 (as double)
        lookup_id = sub_float64(lookup_id, 0x3ff0000000000000, 0);

        if (lookup_id == -1 || lookup_id == 0) {
            return 0;
        }

        bpf_printk("looking up id %llx", lookup_id);
        u64 *parent_id = (u64 *)bpf_map_lookup_elem(&nodejs_parent_map, &lookup_id);
        if (parent_id) {
            return *parent_id;
        }
    }

    return 0;
}

#endif