#ifndef HTTP_TYPES_H
#define HTTP_TYPES_H

#include "vmlinux.h"
#include "map_sizing.h"
#include "bpf_helpers.h"
#include "http_defs.h"
#include "pid_types.h"

#define FULL_BUF_SIZE 160 // should be enough for most URLs, we may need to extend it if not. Must be multiple of 16 for the copy to work.
#define TRACE_BUF_SIZE 1024 // must be power of 2, we do an & to limit the buffer size
#define KPROBES_HTTP2_BUF_SIZE 256
#define KPROBES_HTTP2_RET_BUF_SIZE 64

#define KPROBES_LARGE_RESPONSE_LEN 100000 // 100K and above we try to track the response actual time with kretprobes

#define CONN_INFO_FLAG_TRACE 0x1

#define TRACE_ID_SIZE_BYTES 16
#define SPAN_ID_SIZE_BYTES   8
#define FLAGS_SIZE_BYTES     1
#define TRACE_ID_CHAR_LEN   32
#define SPAN_ID_CHAR_LEN    16
#define FLAGS_CHAR_LEN       2
#define TP_MAX_VAL_LENGTH   55
#define TP_MAX_KEY_LENGTH   11

#define TCP_SEND 1
#define TCP_RECV 0

#define NO_SSL 0
#define WITH_SSL 1

// Struct to keep information on the connections in flight 
// s = source, d = destination
// h = high word, l = low word
// used as hashmap key, must be 4 byte aligned?
typedef struct http_connection_info {
    u8  s_addr[IP_V6_ADDR_LEN];
    u8  d_addr[IP_V6_ADDR_LEN];
    u16 s_port;
    u16 d_port;
} connection_info_t;

typedef struct http_partial_connection_info {
    u8  s_addr[IP_V6_ADDR_LEN];
    u16 s_port;
    u16 d_port;
    u32 tcp_seq;
} partial_connection_info_t;

typedef struct http_pid_connection_info {
    connection_info_t conn;
    u32 pid;
} pid_connection_info_t;

typedef struct tp_info {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    unsigned char parent_id[SPAN_ID_SIZE_BYTES];
    u64 ts;
    u8  flags;
} tp_info_t;

typedef struct tp_info_pid {
    tp_info_t tp;
    u32 pid;
    u8  valid;
} tp_info_pid_t;

// Here we keep the information that is sent on the ring buffer
typedef struct http_info {
    u8 flags; // Must be fist we use it to tell what kind of packet we have on the ring buffer
    connection_info_t conn_info;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    unsigned char buf[FULL_BUF_SIZE] __attribute__ ((aligned (8))); // ringbuffer memcpy complains unless this is 8 byte aligned
    u32 len;
    u32 resp_len;
    u16 status;    
    u8  type;
    u8  ssl;
    // we need this for system wide tracking so we can find the service name
    // also to filter traces from unsolicited processes that share the executable
    // with other instrumented processes
    pid_info pid;
    tp_info_t tp;
} http_info_t;

// Here we keep information on the packets passing through the socket filter
typedef struct protocol_info {
    u32 hdr_len;
    u32 seq;
    u8  flags;
} protocol_info_t;

// Here we keep information on the ongoing filtered connections, PID/TID and connection type
typedef struct http_connection_metadata {
    pid_info pid;
    u8  type;
} http_connection_metadata_t;

typedef struct http2_conn_stream {
    pid_connection_info_t pid_conn;
    u32 stream_id;
} http2_conn_stream_t;

typedef struct http2_grpc_request {
    u8  flags;                           // Must be first
    connection_info_t conn_info;
    u8  data[KPROBES_HTTP2_BUF_SIZE];
    u8  ret_data[KPROBES_HTTP2_RET_BUF_SIZE];
    u8  type;
    int len;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    // we need this for system wide tracking so we can find the service name
    // also to filter traces from unsolicited processes that share the executable
    // with other instrumented processes
    pid_info pid;
    tp_info_t tp;
} http2_grpc_request_t;

// Force emitting struct http_request_trace into the ELF for automatic creation of Golang struct
const http_info_t *unused __attribute__((unused));
const http2_grpc_request_t *unused_http2 __attribute__((unused));

const u8 ip4ip6_prefix[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

#ifdef BPF_DEBUG
static __always_inline void dbg_print_http_connection_info(connection_info_t *info) {
    bpf_printk("[http] s_h = %llx, s_l = %llx, d_h = %llx, d_l = %llx, s_port=%d, d_port=%d",
               *(u64 *)(&info->s_addr),
               *(u64 *)(&info->s_addr[8]),
               *(u64 *)(&info->d_addr),
               *(u64 *)(&info->d_addr[8]),
               info->s_port,
               info->d_port);
}
#else
static __always_inline void dbg_print_http_connection_info(connection_info_t *info) {
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
static __always_inline void sort_connection_info(connection_info_t *info) {
    if (likely_ephemeral_port(info->s_port) && !likely_ephemeral_port(info->d_port)) {
        return;
    }

    if ((likely_ephemeral_port(info->d_port) && !likely_ephemeral_port(info->s_port)) ||
        (info->d_port > info->s_port)) {
        // Only sort if they are explicitly reversed, otherwise always sort source to be the larger
        // of the two ports
        __SWAP(u16, info->s_port, info->d_port);
        u8 tmp_addr[IP_V6_ADDR_LEN];
        __builtin_memcpy(tmp_addr, info->s_addr, sizeof(tmp_addr));
        __builtin_memcpy(info->s_addr, info->d_addr, sizeof(info->s_addr));
        __builtin_memcpy(info->d_addr, tmp_addr, sizeof(info->d_addr));
    }
}

static __always_inline bool client_call(connection_info_t *info) {
    return likely_ephemeral_port(info->s_port) && !likely_ephemeral_port(info->d_port);
}

#endif