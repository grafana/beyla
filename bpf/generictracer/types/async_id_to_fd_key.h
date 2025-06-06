#pragma once

#include <bpfcore/vmlinux.h>

typedef struct async_id_to_fd_key_t {
    u64 pid_tgid;
    u64 async_id;
} async_id_to_fd_key;
