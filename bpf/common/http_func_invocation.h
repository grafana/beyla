#pragma once

#include <bpfcore/vmlinux.h>

#include <common/tp_info.h>

typedef struct http_func_invocation {
    u64 start_monotime_ns;
    tp_info_t tp;
} http_func_invocation_t;
