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

#pragma once

#include <bpfcore/utils.h>

#include <pid/pid_helpers.h>

#include <common/http_types.h>

#define PATH_MAX_LEN 100
#define METHOD_MAX_LEN 7 // Longest method: OPTIONS
#define REMOTE_ADDR_MAX_LEN                                                                        \
    50 // We need 48: 39(ip v6 max) + 1(: separator) + 7(port length max value 65535) + 1(null terminator)
#define HOST_LEN 64 // can be a fully qualified DNS name
#define TRACEPARENT_LEN 55
#define SQL_MAX_LEN 500
#define KAFKA_MAX_LEN 256
#define REDIS_MAX_LEN 256
#define MAX_TOPIC_NAME_LEN 64
#define HOST_MAX_LEN 100
#define SCHEME_MAX_LEN 10
#define HTTP_BODY_MAX_LEN 64
#define HTTP_HEADER_MAX_LEN 100
#define CONTENT_TYPE_KEY_LEN 12 // "content-type" length
#define HTTP_CONTENT_TYPE_MAX_LEN 16

// Trace of an HTTP call invocation. It is instantiated by the return uprobe and forwarded to the
// user space through the events ringbuffer.
typedef struct http_request_trace_t {
    u8 type; // Must be first
    u8 _pad0[1];
    u16 status;
    u8 method[METHOD_MAX_LEN];
    u8 scheme[SCHEME_MAX_LEN];
    u8 _pad1[11];
    u64 go_start_monotime_ns;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    s64 content_length;
    s64 response_length;
    u8 path[PATH_MAX_LEN];
    u8 host[HOST_MAX_LEN];
    tp_info_t tp;
    connection_info_t conn;
    pid_info pid;
} http_request_trace;

typedef struct sql_request_trace_t {
    u8 type; // Must be first
    u8 _pad[1];
    u16 status;
    pid_info pid;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    tp_info_t tp;
    connection_info_t conn;
    u8 sql[SQL_MAX_LEN];
} sql_request_trace;

typedef struct kafka_client_req {
    u8 type; // Must be first
    u8 _pad[7];
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8 buf[KAFKA_MAX_LEN];
    connection_info_t conn;
    pid_info pid;
} kafka_client_req_t;

typedef struct kafka_go_req {
    u8 type; // Must be first
    u8 op;
    u8 _pad0[2];
    pid_info pid;
    connection_info_t conn;
    u8 _pad1[4];
    tp_info_t tp;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u8 topic[MAX_TOPIC_NAME_LEN];
} kafka_go_req_t;

typedef struct redis_client_req {
    u8 type; // Must be first
    u8 err;
    u8 _pad[6];
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    pid_info pid;
    u8 buf[REDIS_MAX_LEN];
    connection_info_t conn;
    tp_info_t tp;
} redis_client_req_t;
