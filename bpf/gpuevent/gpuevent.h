// Copyright (c) Meta Platforms, Inc. and affiliates.
// Copyright Grafana Labs
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
#pragma once

#include <pid/pid.h>

#pragma once
#define TASK_COMM_LEN 16
#define MAX_GPUKERN_ARGS 16

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif

typedef uint64_t stack_trace_t[MAX_STACK_DEPTH];

// This is the struct that will be serialized on the ring buffer and sent to user space
typedef struct gpu_kernel_launch {
    u8 flags; // Must be first, we use it to tell what kind of packet we have on the ring buffer
    u8 _pad[3];
    pid_info pid_info;
    uint64_t kern_func_off;
    int grid_x;
    int grid_y;
    int grid_z;
    int block_x;
    int block_y;
    int block_z;
    uint64_t stream;
    uint64_t args[MAX_GPUKERN_ARGS];
    size_t ustack_sz;
    stack_trace_t ustack;
} gpu_kernel_launch_t;

typedef struct gpu_malloc {
    u8 flags; // Must be first, we use it to tell what kind of packet we have on the ring buffer
    u8 _pad[3];
    pid_info pid_info;
    u64 size;
} gpu_malloc_t;
