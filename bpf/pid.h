#ifndef PID_HELPERS_H
#define PID_HELPERS_H

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

volatile const s32 current_pid = 0;

static __always_inline u32 valid_pid(u64 id) {
    u32 pid = id >> 32;
    // If we are doing system wide instrumenting, accept all PIDs
    if (!current_pid) {
        return pid;
    }

    if (pid != current_pid)
    {
        // some frameworks launch sub-processes for handling requests
        u32 host_ppid = 0;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        if (task)
        {
            host_ppid = BPF_CORE_READ(task, real_parent, tgid);
        }

        if (host_ppid != current_pid)
        {
            return 0;
        }
    }

    return pid;
}

#endif