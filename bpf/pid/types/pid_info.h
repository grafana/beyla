#pragma once

#include <bpfcore/vmlinux.h>

typedef struct pid_info {
    u32 host_pid; // pid as seen by the root cgroup (and by BPF)
    u32 user_pid; // pid as seen by the userspace (for example, inside its container)
    u32 ns;       // pids namespace for the process
} pid_info;
