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
#ifndef GO_TRACEPARENT_H
#define GO_TRACEPARENT_H

#include "utils.h"
#include "stdbool.h"
#include "bpf_dbg.h"
#include "bpf_helpers.h"

#define MAX_BUCKETS 8
#define W3C_KEY_LENGTH 11
#define W3C_VAL_LENGTH 55

#define MAX_REALLOCATION 400
#define MAX_DATA_SIZE 400

#define OFFSET_OF_GO_RUNTIME_HMAP_FIELD_B 9
#define OFFSET_OF_GO_RUNTIME_HMAP_FIELD_BUCKETS 16

struct go_string
{
    char *str;
    s64 len;
};

struct go_slice
{
    void *array;
    s64 len;
    s64 cap;
};

struct go_slice_user_ptr
{
    void *array;
    void *len;
    void *cap;
};

struct go_iface
{
    void *tab;
    void *data;
};

struct map_bucket {
    char tophash[8];
    struct go_string keys[8];
    struct go_slice values[8];
    void *overflow;
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct map_bucket));
    __uint(max_entries, 1);
} golang_mapbucket_storage_map SEC(".maps");

// assumes s2 is all lowercase
static __always_inline int bpf_memicmp(char *s1, char *s2, s32 size)
{
    for (int i = 0; i < size; i++)
    {
        if (s1[i] != s2[i] && s1[i] != (s2[i] - 32)) // compare with each uppercase character
        {
            return i+1;
        }
    }

    return 0;
}

static __always_inline void *extract_traceparent_from_req_headers(void *headers_ptr_ptr)
{
    void *headers_ptr;
    long res;
    res = bpf_probe_read(&headers_ptr, sizeof(headers_ptr), headers_ptr_ptr);
    if (res < 0)
    {
        return NULL;
    }
    u64 headers_count = 0;
    res = bpf_probe_read(&headers_count, sizeof(headers_count), headers_ptr);
    if (res < 0)
    {
        return NULL;
    }
    if (headers_count == 0)
    {
        return NULL;
    }
    unsigned char log_2_bucket_count;
    res = bpf_probe_read(&log_2_bucket_count, sizeof(log_2_bucket_count), headers_ptr + OFFSET_OF_GO_RUNTIME_HMAP_FIELD_B);
    if (res < 0)
    {
        return NULL;
    }
    u64 bucket_count = 1 << log_2_bucket_count;
    void *header_buckets;
    res = bpf_probe_read(&header_buckets, sizeof(header_buckets), headers_ptr + OFFSET_OF_GO_RUNTIME_HMAP_FIELD_BUCKETS);
    if (res < 0)
    {
        return NULL;
    }
    u32 map_id = 0;
    struct map_bucket *map_value = (struct map_bucket *)bpf_map_lookup_elem(&golang_mapbucket_storage_map, &map_id);
    if (!map_value)
    {
        return NULL;
    }

    for (u64 j = 0; j < MAX_BUCKETS; j++)
    {
        if (j >= bucket_count)
        {
            break;
        }
        res = bpf_probe_read(map_value, sizeof(struct map_bucket), header_buckets + (j * sizeof(struct map_bucket)));
        if (res < 0)
        {
            continue;
        }
        for (u64 i = 0; i < 8; i++)
        {
            if (map_value->tophash[i] == 0)
            {
                continue;
            }
            if (map_value->keys[i].len != W3C_KEY_LENGTH)
            {
                continue;
            }
            char current_header_key[W3C_KEY_LENGTH];
            bpf_probe_read(current_header_key, sizeof(current_header_key), map_value->keys[i].str);        
            if (bpf_memicmp(current_header_key, "traceparent", W3C_KEY_LENGTH)) // grpc headers don't get normalized
            {
                continue;
            }
            void *traceparent_header_value_ptr = map_value->values[i].array;
            struct go_string traceparent_header_value_go_str;
            res = bpf_probe_read(&traceparent_header_value_go_str, sizeof(traceparent_header_value_go_str), traceparent_header_value_ptr);
            if (res < 0)
            {
                return NULL;
            }
            if (traceparent_header_value_go_str.len != W3C_VAL_LENGTH)
            {
                continue;
            }
            return traceparent_header_value_go_str.str;
        }
    }
    return NULL;
}

#endif
