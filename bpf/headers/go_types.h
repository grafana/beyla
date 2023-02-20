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

#include "alloc.h"
#include "bpf_helpers.h"

#define MAX_REALLOCATION 400

struct go_string
{
    char *str;
    s32 len;
};

struct go_slice
{
    void *array;
    s32 len;
    s32 cap;
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

static __always_inline struct go_string write_user_go_string(char *str, u32 len)
{
    // Copy chars to userspace
    char *addr = write_target_data((void *)str, len);

    // Build string struct in kernel space
    struct go_string new_string = {};
    new_string.str = addr;
    new_string.len = len;

    // Copy new string struct to userspace
    write_target_data((void *)&new_string, sizeof(new_string));
    return new_string;
}

static __always_inline void append_item_to_slice(struct go_slice *slice, void *new_item, s32 item_size, struct go_slice_user_ptr *slice_user_ptr, void *buff)
{
    if (slice->len < slice->cap)
    {
        // Room available on current array
        bpf_probe_write_user(slice->array + (item_size * slice->len), new_item, item_size);
    }
    else
    {
        // No room on current array - copy to new one of size item_size * (len + 1)
        s32 alloc_size = item_size * slice->len;
        s32 bounded_alloc_size = alloc_size > MAX_REALLOCATION ? MAX_REALLOCATION : (alloc_size < 1 ? 1 : alloc_size);

        // Get buffer
        s32 index = 0;
        void *map_buff = bpf_map_lookup_elem(buff, &index);
        if (!map_buff)
        {
            return;
        }

        // Append to buffer
        bpf_probe_read_user(map_buff, bounded_alloc_size, slice->array);
        bpf_probe_read(map_buff + bounded_alloc_size, item_size, new_item);
        void *new_array = write_target_data(map_buff, bounded_alloc_size + item_size);

        // Update array
        slice->array = new_array;
        long success = bpf_probe_write_user(slice_user_ptr->array, &slice->array, sizeof(slice->array));

        // Update cap
        slice->cap++;
        success = bpf_probe_write_user(slice_user_ptr->cap, &slice->cap, sizeof(slice->cap));
    }

    // Update len
    slice->len++;
    long success = bpf_probe_write_user(slice_user_ptr->len, &slice->len, sizeof(slice->len));
}
