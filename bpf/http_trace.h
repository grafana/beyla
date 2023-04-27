#ifndef HTTP_TRACE_H
#define HTTP_TRACE_H

#include "utils.h"

#define EVENT_HTTP_REQUEST 1
#define EVENT_GRPC_REQUEST 2

#define PATH_MAX_LEN 100
#define METHOD_MAX_LEN 6 // Longest method: DELETE
#define REMOTE_ADDR_MAX_LEN 50 // We need 48: 39(ip v6 max) + 1(: separator) + 7(port length max value 65535) + 1(null terminator)
#define HOST_LEN 256 // can be a fully qualified DNS name

// Trace of an HTTP call invocation. It is instantiated by the return uprobe and forwarded to the
// user space through the events ringbuffer.
typedef struct http_request_trace_t {
    u8  type;
    u64 go_start_monotime_ns;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8  method[METHOD_MAX_LEN];
    u8  path[PATH_MAX_LEN];
    u16 status;
    u8  remote_addr[REMOTE_ADDR_MAX_LEN];
    u64 remote_addr_len;
    u8  host[HOST_LEN];
    u64 host_len;
    u32 host_port;
    s64 content_length;
} __attribute__((packed)) http_request_trace;

#endif