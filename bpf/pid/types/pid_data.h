#pragma once

#include <bpfcore/vmlinux.h>

typedef struct pid_data {
    u32 pid; // parent pid as seen by the userspace (for example, inside its container)
    u32 ns;  // pids namespace for the process
} __attribute__((packed)) pid_data_t;
