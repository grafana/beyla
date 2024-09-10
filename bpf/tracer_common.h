// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef TRACER_COMMON_H
#define TRACER_COMMON_H

#include "pid_types.h"
#include "utils.h"
#include "http_types.h"

#define PATH_MAX_LEN 100
#define METHOD_MAX_LEN 7 // Longest method: OPTIONS
#define REMOTE_ADDR_MAX_LEN 50 // We need 48: 39(ip v6 max) + 1(: separator) + 7(port length max value 65535) + 1(null terminator)
#define HOST_LEN 64 // can be a fully qualified DNS name
#define TRACEPARENT_LEN 55
#define SQL_MAX_LEN 500
#define KAFKA_MAX_LEN 256
#define REDIS_MAX_LEN 256
#define MAX_TOPIC_NAME_LEN 64

// Trace of an HTTP call invocation. It is instantiated by the return uprobe and forwarded to the
// user space through the events ringbuffer.
typedef struct http_request_trace_t {
    u8  type;                           // Must be first
    u64 go_start_monotime_ns;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8  method[METHOD_MAX_LEN];
    u8  path[PATH_MAX_LEN];
    u16 status;
    connection_info_t conn __attribute__ ((aligned (8)));
    s64 content_length;
    tp_info_t tp;

    pid_info pid;
} __attribute__((packed)) http_request_trace;

typedef struct sql_request_trace_t {
    u8  type;                           // Must be first
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8  sql[SQL_MAX_LEN];
    u16 status;
    tp_info_t tp;
    pid_info pid;
} __attribute__((packed)) sql_request_trace;

typedef struct kafka_client_req {
    u8  type;                           // Must be first
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8  buf[KAFKA_MAX_LEN];
    connection_info_t conn __attribute__ ((aligned (8)));
    tp_info_t tp;
    pid_info pid;
} __attribute__((packed)) kafka_client_req_t;

typedef struct kafka_go_req {
    u8  type;                           // Must be first
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8  topic[MAX_TOPIC_NAME_LEN];
    connection_info_t conn __attribute__ ((aligned (8)));
    tp_info_t tp;
    pid_info pid;
    u8 op;
} __attribute__((packed)) kafka_go_req_t;

typedef struct redis_client_req {
    u8  type;                           // Must be first
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8  buf[REDIS_MAX_LEN];
    connection_info_t conn __attribute__ ((aligned (8)));
    tp_info_t tp __attribute__ ((aligned (8)));
    pid_info pid;
    u8 err;
} __attribute__((packed)) redis_client_req_t;

#endif //TRACER_COMMON_H
