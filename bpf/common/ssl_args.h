#pragma once

#include <bpfcore/vmlinux.h>

// Temporary tracking of ssl_read/ssl_read_ex and ssl_write/ssl_write_ex arguments
typedef struct ssl_args {
    u64 ssl;     // SSL struct pointer
    u64 buf;     // pointer to the buffer we read into
    u64 len_ptr; // size_t pointer of the read/written bytes, used only by SSL_read_ex and SSL_write_ex
} ssl_args_t;
