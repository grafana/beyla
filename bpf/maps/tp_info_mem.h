#pragma once

#include <bpfcore/utils.h>

#include <common/tp_info.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, int);
    __type(value, tp_info_pid_t);
    __uint(max_entries, 1);
} tp_info_mem SEC(".maps");
