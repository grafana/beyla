// Copyright (c) Meta Platforms, Inc. and affiliates.
// Copyright Grafana Labs
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

#pragma once
#define TASK_COMM_LEN 16
#define MAX_GPUKERN_ARGS 16

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 128
#endif

typedef uint64_t stack_trace_t[MAX_STACK_DEPTH];

struct gpukern_sample {
  int pid, ppid;
  char comm[TASK_COMM_LEN];
  uint64_t kern_func_off;
  int grid_x, grid_y, grid_z;
  int block_x, block_y, block_z;
  uint64_t stream;
  uint64_t args[MAX_GPUKERN_ARGS];
  size_t ustack_sz;
  stack_trace_t ustack;
};