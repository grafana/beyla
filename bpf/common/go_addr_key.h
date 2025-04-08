#pragma once

#include <bpfcore/vmlinux.h>

typedef struct go_addr_key {
    u64 pid;  // PID of the process
    u64 addr; // Address of the goroutine
} go_addr_key_t;
