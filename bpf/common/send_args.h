#pragma once

#include <common/connection_info.h>

typedef struct send_args {
    pid_connection_info_t p_conn;
    u64 size;
    u64 sock_ptr;
} send_args_t;
