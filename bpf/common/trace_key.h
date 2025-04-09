#pragma once

#include <bpfcore/vmlinux.h>

#include <pid/pid_helpers.h>

typedef struct trace_key {
    u64 extra_id;    // pids namespace for the process
    pid_key_t p_key; // pid key as seen by the userspace (for example, inside its container)
    u8 _pad[4];
} trace_key_t;
