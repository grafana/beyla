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

#include <logger/bpf_dbg.h>

static __inline int
read_go_byte_arr(char *name, void *base_ptr, u8 offset, void *field, u64 *size_ptr, u64 max_size) {
    void *ptr = 0;
    if (bpf_probe_read(&ptr, sizeof(ptr), (void *)(base_ptr + offset)) != 0) {
        bpf_dbg_printk("can't read ptr for %s", name);
        return 0;
    }

    if (bpf_probe_read(size_ptr, sizeof(u64), (void *)(base_ptr + (offset + 8))) != 0) {
        bpf_dbg_printk("can't read len for %s", name);
        return 0;
    }

    u64 size = max_size < *size_ptr ? max_size : *size_ptr;
    if (bpf_probe_read(field, size, ptr)) {
        bpf_dbg_printk("can't read string for %s", name);
        return 0;
    }

    return 1;
}
