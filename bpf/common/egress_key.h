#pragma once

#include <bpfcore/vmlinux.h>

typedef struct egress_key {
    u16 s_port;
    u16 d_port;
} egress_key_t;
