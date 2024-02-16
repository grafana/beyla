#ifndef PID_H
#define PID_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "pid_types.h"

#define MAX_CONCURRENT_PIDS 3000 // estimate: 1000 concurrent processes (including children) * 3 namespaces per pid

volatile const s32 filter_pids = 0;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);    
    __uint(max_entries, MAX_CONCURRENT_PIDS);
    __type(key, pid_key_t);
    __type(value, u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} valid_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_PIDS);
    __type(key, u32);
    __type(value, u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pid_cache SEC(".maps");

static __always_inline u32 valid_pid(u64 id) {
    u32 host_pid = id >> 32;
    // If we are doing system wide instrumenting, accept all PIDs
    if (!filter_pids) {
        return host_pid;
    }

    u32 *found = bpf_map_lookup_elem(&pid_cache, &host_pid);
    if (found) {
        return *found;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    int ns_pid = 0;
    int ns_ppid = 0;
    u32 pid_ns_id = 0;

    ns_pid_ppid(task, &ns_pid, &ns_ppid, &pid_ns_id);

    if (ns_pid != 0) {
        pid_key_t p_key = {
            .pid = ns_pid,
            .ns = pid_ns_id
        };

        u32 *found_ns_pid = bpf_map_lookup_elem(&valid_pids, &p_key);

        if (found_ns_pid) {
            bpf_map_update_elem(&pid_cache, &host_pid, &ns_pid, BPF_ANY);
            return ns_pid;
        } else if (ns_ppid != 0) {
            pid_key_t pp_key = {
                .pid = ns_ppid,
                .ns = pid_ns_id
            };

            u32 *found_ns_ppid = bpf_map_lookup_elem(&valid_pids, &pp_key);
            
            if (found_ns_ppid) {
                bpf_map_update_elem(&pid_cache, &host_pid, &ns_pid, BPF_ANY);

                return ns_pid;
            }
        }
    }

    return 0;
}

#endif