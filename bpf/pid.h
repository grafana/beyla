#ifndef PID_HELPERS_H
#define PID_HELPERS_H

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#define MAX_CONCURRENT_PIDS 1000

volatile const s32 filter_pids = 0;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_PIDS);
    __type(key, u32);
    __type(value, u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} valid_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONCURRENT_PIDS);
    __type(key, u32);
    __type(value, u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pid_cache SEC(".maps");

typedef struct pid_info_t {
    u32 host_pid;   // pid as seen by the root cgroup (and by BPF)
    u32 user_pid;   // pid as seen by the userspace (for example, inside its container)
    u32 namespace;  // pids namespace for the process
} __attribute__((packed)) pid_info;

// Good resource on this: https://mozillazg.com/2022/05/ebpf-libbpfgo-get-process-info-en.html
// Using bpf_get_ns_current_pid_tgid is too restrictive for us
static __always_inline void ns_pid_ppid(struct task_struct *task, int *pid, int *ppid, u32 *pid_ns_id) {
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
    pid->namespace = (u32)ns.inum;
}

static __always_inline u32 pid_from_pid_tgid(u64 id) {
    return (u32)(id >> 32);
}

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
        u32 *found_ns_pid = bpf_map_lookup_elem(&valid_pids, &ns_pid);

        if (found_ns_pid && (pid_ns_id == *found_ns_pid)) {
            bpf_map_update_elem(&pid_cache, &host_pid, &ns_pid, BPF_ANY);
            return ns_pid;
        } else if (ns_ppid != 0) {
            u32 *found_ns_ppid = bpf_map_lookup_elem(&valid_pids, &ns_ppid);
            
            if (found_ns_ppid && (pid_ns_id == *found_ns_ppid)) {
                bpf_map_update_elem(&pid_cache, &host_pid, &ns_pid, BPF_ANY);

                return ns_pid;
            }
        }
    }

    return 0;
}

#endif