#ifndef TC_COMMON_H
#define TC_COMMON_H

#include "vmlinux.h"
#include "bpf_helpers.h"

enum { MAX_INLINE_LEN = 0x3ff };

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

#endif