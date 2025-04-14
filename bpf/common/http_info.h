#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/tp_info.h>

#include <pid/pid_helpers.h>

#define FULL_BUF_SIZE 256

// Here we keep the information that is sent on the ring buffer
typedef struct http_info {
    u8 flags; // Must be fist we use it to tell what kind of packet we have on the ring buffer
    u8 type;
    u8 ssl;
    u8 delayed;
    connection_info_t conn_info;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u64 extra_id;
    tp_info_t tp;
    pid_info pid;
    u32 len;
    u32 resp_len;
    u32 task_tid;
    u16 status;
    unsigned char buf[FULL_BUF_SIZE];
    u8 _pad[6];
} http_info_t;
