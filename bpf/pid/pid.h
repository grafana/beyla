#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <logger/bpf_dbg.h>

#include <pid/maps/pid_cache.h>
#include <pid/maps/valid_pids.h>

volatile const s32 filter_pids = 0;

enum { k_prime_hash = 192053 }; // closest prime to k_max_concurrent_pids * 64

typedef struct pid_key {
    u32 tid; // tid as seen by the userspace (for example, inside its container)
    u32 pid; // parent pid as seen by the userspace (for example, inside its container)
    u32 ns;  // pids namespace for the process
} __attribute__((packed)) pid_key_t;

typedef struct pid_data {
    u32 pid; // parent pid as seen by the userspace (for example, inside its container)
    u32 ns;  // pids namespace for the process
} __attribute__((packed)) pid_data_t;

typedef struct pid_info_t {
    u32 host_pid; // pid as seen by the root cgroup (and by BPF)
    u32 user_pid; // pid as seen by the userspace (for example, inside its container)
    u32 ns;       // pids namespace for the process
} __attribute__((packed)) pid_info;

// Good resource on this: https://mozillazg.com/2022/05/ebpf-libbpfgo-get-process-info-en.html
// Using bpf_get_ns_current_pid_tgid is too restrictive for us
static __always_inline void
ns_pid_ppid(struct task_struct *task, int *pid, int *ppid, u32 *pid_ns_id) {
    struct upid upid;

    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);

    *pid = upid.nr;
    unsigned int p_level = BPF_CORE_READ(task, real_parent, nsproxy, pid_ns_for_children, level);

    struct pid *ns_ppid = (struct pid *)BPF_CORE_READ(task, real_parent, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_ppid->numbers[p_level]);
    *ppid = upid.nr;

    struct ns_common ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns);
    *pid_ns_id = ns.inum;
}

// sets the pid_info value from the current task
static __always_inline void task_pid(pid_info *pid) {
    struct upid upid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // set host-side PID
    pid->host_pid = (u32)BPF_CORE_READ(task, tgid);

    // set user-side PID
    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);
    pid->user_pid = (u32)upid.nr;

    // set PIDs namespace
    struct ns_common ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns);
    pid->ns = (u32)ns.inum;
}

static __always_inline u32 get_task_tid() {
    struct upid upid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // https://github.com/torvalds/linux/blob/556e2d17cae620d549c5474b1ece053430cd50bc/kernel/pid.c#L324 (type is )
    // set user-side PID
    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);

    return (u32)upid.nr;
}

static __always_inline void task_tid(pid_key_t *tid) {
    struct upid upid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // https://github.com/torvalds/linux/blob/556e2d17cae620d549c5474b1ece053430cd50bc/kernel/pid.c#L324 (type is )
    // set user-side PID
    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);
    tid->tid = (u32)upid.nr;
    ns_pid = (struct pid *)BPF_CORE_READ(task, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);
    tid->pid = (u32)upid.nr;

    // set PIDs namespace
    struct ns_common ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns);
    tid->ns = (u32)ns.inum;
}

static __always_inline u32 pid_from_pid_tgid(u64 id) {
    return (u32)(id >> 32);
}

static __always_inline u64 to_pid_tgid(u32 pid, u32 tid) {
    return (u64)((u64)pid << 32) | tid;
}

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
    // If we are doing system wide instrumenting, accept all PIDs
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
