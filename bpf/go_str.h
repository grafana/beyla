#ifndef GO_STR_H
#define GO_STR_H

#include "utils.h"

static __inline int read_go_str(char *name, void *base_ptr, u8 offset, void *field, u64 max_size) {
    void *ptr = 0;
    if (bpf_probe_read(&ptr, sizeof(ptr), (void *)(base_ptr + offset)) != 0) {
        bpf_printk("can't read ptr for %s", name);
        return 0;
    }

    u64 len = 0;
    if (bpf_probe_read(&len, sizeof(len), (void *)(base_ptr + (offset + 8))) != 0) {
        bpf_printk("can't read len for %s", name);
        return 0;
    }

    u64 size = max_size < len ? max_size : len;
    if (bpf_probe_read(field, size, ptr)) {
        bpf_printk("can't read string for %s", name);
        return 0;
    }

    // put in a null terminator if we are not at max_size
    if (size < max_size) {
        char null = 0;
        bpf_probe_read((char *)field + size, 1, &null);
    }

    return 1;
}

#endif