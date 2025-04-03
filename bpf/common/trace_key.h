#pragma once

#include <bpfcore/vmlinux.h>

#include <pid/pid_helpers.h>

typedef struct trace_key {
    pid_key_t p_key; // pid key as seen by the userspace (for example, inside its container)
    u64 extra_id;    // pids namespace for the process
} __attribute__((packed)) trace_key_t;
