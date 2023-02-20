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

#include "bpf_helpers.h"

#define MAX_ENTRIES 50

// Injected in init
volatile const u32 total_cpus;
volatile const u64 start_addr;
volatile const u64 end_addr;

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, s32);
    __type(value, u64);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} alloc_map SEC(".maps");

static __always_inline u64 get_area_start()
{
    s64 partition_size = (end_addr - start_addr) / total_cpus;
    u32 current_cpu = bpf_get_smp_processor_id();
    s32 start_index = 0;
    u64 *start = (u64 *)bpf_map_lookup_elem(&alloc_map, &start_index);
    if (start == NULL || *start == 0)
    {
        u64 current_start_addr = start_addr + (partition_size * current_cpu);
        bpf_map_update_elem(&alloc_map, &start_index, &current_start_addr, BPF_ANY);
        return current_start_addr;
    }
    else
    {
        return *start;
    }
}

static __always_inline u64 get_area_end(u64 start)
{
    s64 partition_size = (end_addr - start_addr) / total_cpus;
    s32 end_index = 1;
    u64 *end = (u64 *)bpf_map_lookup_elem(&alloc_map, &end_index);
    if (end == NULL || *end == 0)
    {
        u64 current_end_addr = start + partition_size;
        bpf_map_update_elem(&alloc_map, &end_index, &current_end_addr, BPF_ANY);
        return current_end_addr;
    }
    else
    {
        return *end;
    }
}

static __always_inline void *write_target_data(void *data, s32 size)
{
    if (!data || data == NULL)
    {
        return NULL;
    }

    u64 start = get_area_start();
    u64 end = get_area_end(start);
    if (end - start < size)
    {
        bpf_printk("reached end of CPU memory block, going to the start again");
        s32 start_index = 0;
        bpf_map_delete_elem(&alloc_map, &start_index);
        start = get_area_start();
    }

    void *target = (void *)start;
    long success = bpf_probe_write_user(target, data, size);
    if (success == 0)
    {
        s32 start_index = 0;
        u64 updated_start = start + size;
        bpf_map_update_elem(&alloc_map, &start_index, &updated_start, BPF_ANY);
        return target;
    }
    else
    {
        bpf_printk("failed to write to userspace, error code: %d, addr: %lx, size: %d", success, target, size);
        return NULL;
    }
}
