#ifndef TC_COMMON_H
#define TC_COMMON_H

#include "vmlinux.h"
#include "bpf_helpers.h"

enum { MAX_INLINE_LEN = 0x3ff };

const char TP[] = "Traceparent: 00-00000000000000000000000000000000-0000000000000000-01\r\n";
const u32 EXTEND_SIZE = sizeof(TP) - 1;
const char TP_PREFIX[] = "Traceparent: ";
const u32 TP_PREFIX_SIZE = sizeof(TP_PREFIX) - 1;

static __always_inline unsigned char *
memchar(unsigned char *haystack, char needle, const unsigned char *end, u32 size) {
    for (u32 i = 0; i < size; ++i) {
        if (&haystack[i] >= end) {
            break;
        }

        if (haystack[i] == needle) {
            return &haystack[i];
        }
    }

    return 0;
}

static __always_inline unsigned char *
find_first_of(unsigned char *begin, unsigned char *end, char ch) {
    return memchar(begin, ch, end, MAX_INLINE_LEN);
}

static __always_inline int
memchar_pos(unsigned char *haystack, char needle, const unsigned char *end, u32 size) {
    for (u32 i = 0; i < size; ++i) {
        if (&haystack[i] >= end) {
            break;
        }

        if (haystack[i] == needle) {
            return i;
        }
    }

    return -1;
}

static __always_inline int find_first_pos_of(unsigned char *begin, unsigned char *end, char ch) {
    return memchar_pos(begin, ch, end, MAX_INLINE_LEN);
}

static __always_inline void *ctx_data(struct __sk_buff *ctx) {
    void *data;

    asm("%[res] = *(u32 *)(%[base] + %[offset])"
        : [res] "=r"(data)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct __sk_buff, data)), "m"(*ctx));

    return data;
}

static __always_inline void *ctx_data_end(struct __sk_buff *ctx) {
    void *data_end;

    asm("%[res] = *(u32 *)(%[base] + %[offset])"
        : [res] "=r"(data_end)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct __sk_buff, data_end)), "m"(*ctx));

    return data_end;
}
#endif