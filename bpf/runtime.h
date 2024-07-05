#ifndef RUNTIME_SUPPORT_H
#define RUNTIME_SUPPORT_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "pid_types.h"
#include "nodejs.h"

static __always_inline u64 extra_runtime_id() {
    u64 id = bpf_get_current_pid_tgid();

    u64 *active_node_id = (u64 *)bpf_map_lookup_elem(&active_nodejs_ids, &id);
    if (active_node_id) {
        return *active_node_id;
    }

    return 0;
}

static __always_inline u64 parent_runtime_id(pid_key_t *p_key, u64 runtime_id) {
    u64 *parent_id = (u64 *)bpf_map_lookup_elem(&nodejs_parent_map, &runtime_id);
    if (parent_id) {
        return *parent_id;
    }

    return 0;
}

#endif