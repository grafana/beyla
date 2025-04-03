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

static __always_inline int
read_go_str_n(char *name, void *base_ptr, u64 len, void *field, u64 max_size) {
    u64 size = max_size < len ? max_size : len;
    if (bpf_probe_read(field, size, base_ptr)) {
        bpf_dbg_printk("can't read string for %s", name);
        return 0;
    }

    // put in a null terminator if we are not at max_size
    if (size < max_size) {
        ((char *)field)[size] = 0;
    }

    return 1;
}

static __always_inline int
read_go_str(char *name, void *base_ptr, u8 offset, void *field, u64 max_size) {
    void *ptr = 0;
    if (bpf_probe_read(&ptr, sizeof(ptr), (void *)(base_ptr + offset)) != 0) {
        bpf_dbg_printk("can't read ptr for %s", name);
        return 0;
    }

    u64 len = 0;
    if (bpf_probe_read(&len, sizeof(len), (void *)(base_ptr + (offset + 8))) != 0) {
        bpf_dbg_printk("can't read len for %s", name);
        return 0;
    }

    u64 size = max_size < len ? max_size : len;
    if (bpf_probe_read(field, size, ptr)) {
        bpf_dbg_printk("can't read string for %s", name);
        return 0;
    }

    // put in a null terminator if we are not at max_size
    if (size < max_size) {
        ((char *)field)[size] = 0;
    }

    return 1;
}
