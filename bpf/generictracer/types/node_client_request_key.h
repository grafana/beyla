#pragma once

#include <bpfcore/vmlinux.h>

typedef struct node_client_request_key_t {
    u64 pid_tgid;
    u64 client_request_id;
} node_client_request_key;
