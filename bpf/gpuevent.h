// Copyright (c) Meta Platforms, Inc. and affiliates.
// Copyright Grafana Labs
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
#ifndef GPU_EVENT_H
#define GPU_EVENT_H

#include "pid_types.h"

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
    pid_info pid_info;
    char comm[TASK_COMM_LEN];
    uint64_t kern_func_off;
    int grid_x, grid_y, grid_z;
    int block_x, block_y, block_z;
    uint64_t stream;
    uint64_t args[MAX_GPUKERN_ARGS];
    size_t ustack_sz;
    stack_trace_t ustack;
} __attribute__((packed)) gpu_kernel_launch_t;

#endif