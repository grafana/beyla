#pragma once

#include <common/connection_info.h>

typedef struct send_args {
    pid_connection_info_t p_conn;
    u64 size;
    u64 sock_ptr;
    u16 orig_dport;
    u8 _pad[6];
} send_args_t;
