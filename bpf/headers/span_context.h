// Copyright The OpenTelemetry Authors
//
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

#ifndef _SPAN_CONTEXT_H_
#define _SPAN_CONTEXT_H_

#include "otel_utils.h"

#define SPAN_CONTEXT_STRING_SIZE 55
#define MAX_CONCURRENT_SPANS 100

struct span_context
{
    unsigned char TraceID[TRACE_ID_SIZE];
    unsigned char SpanID[SPAN_ID_SIZE];
};

static __always_inline struct span_context generate_span_context()
{
    struct span_context context = {};
    generate_random_bytes(context.TraceID, TRACE_ID_SIZE);
    generate_random_bytes(context.SpanID, SPAN_ID_SIZE);
    return context;
}

static __always_inline void span_context_to_w3c_string(struct span_context *ctx, char *buff)
{
    // W3C format: version (2 chars) - trace id (32 chars) - span id (16 chars) - sampled (2 chars)
    char *out = buff;

    // Write version
    *out++ = '0';
    *out++ = '0';
    *out++ = '-';

    // Write trace id
    bytes_to_hex_string(ctx->TraceID, TRACE_ID_SIZE, out);
    out += TRACE_ID_STRING_SIZE;
    *out++ = '-';

    // Write span id
    bytes_to_hex_string(ctx->SpanID, SPAN_ID_SIZE, out);
    out += SPAN_ID_STRING_SIZE;
    *out++ = '-';

    // Write sampled
    *out++ = '0';
    *out = '1';
}

static __always_inline void w3c_string_to_span_context(char *str, struct span_context *ctx)
{
    u32 trace_id_start_pos = 3;
    u32 span_id_start_pod = 36;
    hex_string_to_bytes(str + trace_id_start_pos, TRACE_ID_STRING_SIZE, ctx->TraceID);
    hex_string_to_bytes(str + span_id_start_pod, SPAN_ID_STRING_SIZE, ctx->SpanID);
}

#endif
