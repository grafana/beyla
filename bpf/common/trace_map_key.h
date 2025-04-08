#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>

typedef struct trace_map_key {
    connection_info_t conn;
    u32 type;
} trace_map_key_t;
