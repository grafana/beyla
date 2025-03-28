#pragma once

#include <bpfcore/vmlinux.h>

#include <common/sizes.h>

// When sock_msg is installed it disables the kprobes attached to tcp_sendmsg.
// We use this data structure to provide the buffer to the tcp_sendmsg logic,
// because we can't read the bvec physical pages.
typedef struct msg_buffer {
    u8 buf[KPROBES_HTTP2_BUF_SIZE];
    u16 pos;
} msg_buffer_t;
