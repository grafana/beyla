#pragma once

#include <bpfcore/vmlinux.h>

typedef struct pid_key {
    u32 tid; // tid as seen by the userspace (for example, inside its container)
    u32 pid; // parent pid as seen by the userspace (for example, inside its container)
    u32 ns;  // pids namespace for the process
} pid_key_t;
