#ifndef PID_HELPERS_H
#define PID_HELPERS_H

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

volatile const s32 current_pid = 0;

// Good resource on this: https://mozillazg.com/2022/05/ebpf-libbpfgo-get-process-info-en.html
// Using bpf_get_ns_current_pid_tgid seems way too restrictive
static __always_inline void ns_pid_ppid(int *pid, int *ppid) {
    struct upid upid;    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);

    *pid = upid.nr;
    unsigned int p_level = BPF_CORE_READ(task, real_parent, nsproxy, pid_ns_for_children, level);
    
    struct pid *ns_ppid = (struct pid *)BPF_CORE_READ(task, real_parent, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_ppid->numbers[p_level]);
    *ppid = upid.nr;
}

static __always_inline u32 pid_from_pid_tgid(u64 id) {
    return (u32)(id >> 32);
}

static __always_inline u32 valid_pid(u64 id) {
    u32 pid = id >> 32;
    // If we are doing system wide instrumenting, accept all PIDs
    if (!current_pid) {
        return pid;
    }

    if (pid != current_pid) {
        // some frameworks launch sub-processes for handling requests
        u32 host_ppid = 0;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task) {
            host_ppid = BPF_CORE_READ(task, real_parent, tgid);
        }

        if (host_ppid != current_pid) {
            // let's see if we are in a container pid space
            int ns_pid = 0;
            int ns_ppid = 0;

            ns_pid_ppid(&ns_pid, &ns_ppid);

            if (current_pid == ns_pid || current_pid == ns_ppid) {
                return ns_pid;
            }

            return 0;
        }
    }

    return pid;
}

#endif