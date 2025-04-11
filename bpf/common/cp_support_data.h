#pragma once

#include <bpfcore/vmlinux.h>

#include <common/trace_key.h>

// Data structure to support context propagation for thread pools
typedef struct cp_support_data {
    trace_key_t t_key;
    u8 real_client;
    u8 _pad[7];
} cp_support_data_t;
