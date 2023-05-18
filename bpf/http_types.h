#ifndef HTTP_TYPES_H
#define HTTP_TYPES_H

#include "common.h"
#include "bpf_helpers.h"
#include "http_defs.h"

#define F_HTTP_IP4 0x1
#define F_HTTP_IP6 0x2

#define BUFFER_SIZE 192

// Struct to keep information on the connections in flight 
// s = source, d = destination
// h = high word, l = low word
// used as hashmap key, must be 4 byte aligned?
typedef struct http_connection_info {
    u64 s_h;
    u64 s_l;
    u64 d_h;
    u64 d_l;
    u16 s_port;
    u16 d_port;
    u32 flags;
} http_connection_info_t;


// Here we keep the information that is sent on the ring buffer
typedef struct http_info {
    http_connection_info_t info;
    u64 req_start_monotime_ns;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8  request_method;
    u16 response_status_code;
    unsigned char buf[BUFFER_SIZE];
} http_info_t;

// Force emitting struct http_request_trace into the ELF for automatic creation of Golang struct
const http_info_t *unused __attribute__((unused));

#if defined(__TARGET_ARCH_arm64)
// Copied from Linux include/uapi/asm/ptrace.h to make ARM64 happy
struct user_pt_regs {
	u64		regs[31];
	u64		sp;
	u64		pc;
	u64		pstate;
};
#endif

#ifdef BPF_DEBUG
static __always_inline void dbg_print_http_connection_info(http_connection_info_t *info) {
    bpf_printk("[http info] s_l = %llx, s_h = %llx, d_l = %llx, d_h = %llx, s_port=%d, "
               "d_port=%d, flags=%llx",
               info->s_l,
               info->s_h,
               info->d_l,
               info->d_h,
               info->s_port,
               info->d_port,
               info->flags);
}
#else
static __always_inline void dbg_print_http_connection_info(http_connection_info_t *info) {
}
#endif

static __always_inline bool likely_ephemeral_port(u16 port) {
    return port >= EPHEMERAL_PORT_MIN;
}

#define __SWAP(T, x, y)                                                                            \
    {                                                                                              \
        T TMP = x;                                                                                 \
        x = y;                                                                                     \
        y = TMP;                                                                                   \
    }

// Since we track both send and receive connections, we need to sort the source and destination
// pairs in a standardized way, we choose the server way of sorting, such that the ephemeral port
// on the client is first.
static __always_inline void sort_connection_info(http_connection_info_t *info) {
    if (likely_ephemeral_port(info->s_port) && !likely_ephemeral_port(info->d_port)) {
        return;
    }

    if ((likely_ephemeral_port(info->d_port) && !likely_ephemeral_port(info->s_port)) ||
        (info->d_port > info->s_port)) {
        // Only sort if they are explicitly reversed, otherwise always sort source to be the larger
        // of the two ports
        __SWAP(u16, info->s_port, info->d_port);
        __SWAP(u64, info->s_l, info->d_l);
        __SWAP(u64, info->s_h, info->d_h);
    }
}

#endif