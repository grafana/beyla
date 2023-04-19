#ifndef GO_BYTE_ARR_H
#define GO_BYTE_ARR_H

#include "utils.h"

static __inline int read_go_byte_arr(char *name, void *base_ptr, u8 offset, void *field, u64 *size_ptr, u64 max_size) {
    void *ptr = 0;
    if (bpf_probe_read(&ptr, sizeof(ptr), (void *)(base_ptr + offset)) != 0) {
        bpf_printk("can't read ptr for %s", name);
        return 0;
    }

    if (bpf_probe_read(size_ptr, sizeof(u64), (void *)(base_ptr + (offset + 8))) != 0) {
        bpf_printk("can't read len for %s", name);
        return 0;
    }

    u64 size = max_size < *size_ptr ? max_size : *size_ptr;
    if (bpf_probe_read(field, size, ptr)) {
        bpf_printk("can't read string for %s", name);
        return 0;
    }

    return 1;
}

#endif