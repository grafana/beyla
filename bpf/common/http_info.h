#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/tp_info.h>

#include <pid/pid.h>

#define FULL_BUF_SIZE 256

// Here we keep the information that is sent on the ring buffer
typedef struct http_info {
    u8 flags; // Must be fist we use it to tell what kind of packet we have on the ring buffer
    connection_info_t conn_info;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    unsigned char buf[FULL_BUF_SIZE]
        __attribute__((aligned(8))); // ringbuffer memcpy complains unless this is 8 byte aligned
    u32 len;
    u32 resp_len;
    u16 status;
    u8 type;
    u8 ssl;
    // we need this for system wide tracking so we can find the service name
    // also to filter traces from unsolicited processes that share the executable
    // with other instrumented processes
    pid_info pid;
    tp_info_t tp;
    u64 extra_id;
    u32 task_tid;
    u8 delayed;
} http_info_t;
