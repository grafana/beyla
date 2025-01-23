#ifndef TC_COMMON_H
#define TC_COMMON_H

#include "vmlinux.h"
#include "bpf_helpers.h"

enum { MAX_INLINE_LEN = 0x3ff };

const char TP[] = "Traceparent: 00-00000000000000000000000000000000-0000000000000000-01\r\n";
const char INV_TP[] = "W3C-BeylaID: 00-00000000000000000000000000000000-0000000000000000-01\r\n";
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
memchar_pos(unsigned const char *haystack, char needle, const unsigned char *end, u32 size) {
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

static __always_inline void
sk_msg_read_remote_ip6(struct sk_msg_md *ctx, u32 *res) { //NOLINT(readability-non-const-parameter)
    asm("%[res0] = *(u32 *)(%[base] + %[offset] + 0)\n"
        "%[res1] = *(u32 *)(%[base] + %[offset] + 4)\n"
        "%[res2] = *(u32 *)(%[base] + %[offset] + 8)\n"
        "%[res3] = *(u32 *)(%[base] + %[offset] + 12)\n"
        : [res0] "=r"(res[0]), [res1] "=r"(res[1]), [res2] "=r"(res[2]), [res3] "=r"(res[3])
        : [base] "r"(ctx), [offset] "i"(offsetof(struct sk_msg_md, remote_ip6)), "m"(*ctx));
}

static __always_inline void
sk_msg_read_local_ip6(struct sk_msg_md *ctx, u32 *res) { //NOLINT(readability-non-const-parameter)
    asm("%[res0] = *(u32 *)(%[base] + %[offset] + 0)\n"
        "%[res1] = *(u32 *)(%[base] + %[offset] + 4)\n"
        "%[res2] = *(u32 *)(%[base] + %[offset] + 8)\n"
        "%[res3] = *(u32 *)(%[base] + %[offset] + 12)\n"
        : [res0] "=r"(res[0]), [res1] "=r"(res[1]), [res2] "=r"(res[2]), [res3] "=r"(res[3])
        : [base] "r"(ctx), [offset] "i"(offsetof(struct sk_msg_md, local_ip6)), "m"(*ctx));
}

static __always_inline u32 sk_msg_remote_port(struct sk_msg_md *ctx) {
    u32 data;

    asm("%[res] = *(u32 *)(%[base] + %[offset])"
        : [res] "=r"(data)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct sk_msg_md, remote_port)), "m"(*ctx));

    return data;
}

static __always_inline u32 sk_msg_local_port(struct sk_msg_md *ctx) {
    u32 data;

    asm("%[res] = *(u32 *)(%[base] + %[offset])"
        : [res] "=r"(data)
        : [base] "r"(ctx), [offset] "i"(offsetof(struct sk_msg_md, local_port)), "m"(*ctx));

    return data;
}
#endif
