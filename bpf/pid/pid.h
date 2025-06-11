#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <logger/bpf_dbg.h>

#include <pid/maps/pid_cache.h>
#include <pid/maps/valid_pids.h>

#include <pid/pid_helpers.h>

#include <pid/types/pid_data.h>

volatile const s32 filter_pids = 0;

enum { k_prime_hash = 192053 }; // closest prime to k_max_concurrent_pids * 64

static __always_inline u8 pid_matches(pid_data_t *p) {
    // combine the namespace id and the pid into one single u64
    u64 k = (((u64)p->ns) << 32) | p->pid;

    // divide with prime number lower than max pids * 64, modulo with primes gives good hash functions
    u32 h = (u32)(k % k_prime_hash);
    u32 segment = h / 64; // divide by the segment size (8 bytes) to find the segment
    u32 bit = h & 63;     // lowest 64 bits gives us the placement inside the segment

    u64 *v = bpf_map_lookup_elem(&valid_pids, &segment);
    if (!v) {
        // This is an error of some kind, we should always find the segment
        bpf_dbg_printk("Error looking up PID segment %d", segment);
        return 1;
    }

    return ((*v) >> bit) & 1;
}

static __always_inline u32 valid_pid(u64 id) {
    u32 a_pid = id >> 32;
    // accept all PIDs if debugging OTEL_EBPF_BPF_PID_FILTER_OFF option is set
    if (!filter_pids) {
        return a_pid;
    }

    u32 *found = bpf_map_lookup_elem(&pid_cache, &a_pid);
    if (found) {
        return *found;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    int ns_ppid = 0;
    u32 pid_ns_id = 0;

    // we reuse the same stack location for the namespaced pid to save
    // on stack space
    ns_pid_ppid(task, (int *)&a_pid, &ns_ppid, &pid_ns_id);

    if (a_pid != 0) {
        pid_data_t p_key = {.pid = a_pid, .ns = pid_ns_id};

        u8 found_ns_pid = pid_matches(&p_key);

        if (found_ns_pid) {
            bpf_map_update_elem(&pid_cache, &a_pid, &a_pid, BPF_ANY);
            return a_pid;
        } else if (ns_ppid != 0) {
            pid_data_t pp_key = {.pid = ns_ppid, .ns = pid_ns_id};

            u8 found_ns_ppid = pid_matches(&pp_key);

            if (found_ns_ppid) {
                bpf_map_update_elem(&pid_cache, &a_pid, &a_pid, BPF_ANY);

                return a_pid;
            }
        }
    }

    return 0;
}
