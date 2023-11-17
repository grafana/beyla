#ifndef TRACE_UTIL_H
#define TRACE_UTIL_H

#include "utils.h"

// 55+13
#define TRACE_PARENT_HEADER_LEN 68

static unsigned char *hex = (unsigned char *)"0123456789abcdef";
static unsigned char *reverse_hex = (unsigned char *)
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xff\xff\xff\xff\xff\xff" 
		"\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

static __always_inline void urand_bytes(unsigned char *buf, u32 size) {
    for (int i = 0; i < size; i += sizeof(u32)) {
        *((u32 *)&buf[i]) = bpf_get_prandom_u32();
    }
}

static __always_inline void decode_hex(unsigned char *dst, unsigned char *src, int src_len) {
    for (int i = 1, j = 0; i < src_len; i +=2) {
        unsigned char p = src[i-1];
        unsigned char q = src[i];

        unsigned char a = reverse_hex[p & 0xff];
        unsigned char b = reverse_hex[q & 0xff];

        a = a & 0x0f;
        b = b & 0x0f;

        dst[j++] = ((a << 4) | b) & 0xff;
    }
}

static __always_inline void encode_hex(unsigned char *dst, unsigned char *src, int src_len) {
    for (int i = 0, j = 0; i < src_len; i++) {
        unsigned char p = src[i];
        dst[j++] = hex[(p >> 4) & 0xff];
        dst[j++] = hex[p & 0x0f];
    }
}


static __always_inline bool is_traceparent(unsigned char *p) {
    if (((p[0] == 'T') || (p[0] == 't')) && (p[1] == 'r') && (p[2] == 'a') && (p[3] == 'c') && 
        (p[4] == 'e') && (p[5] == 'p') && (p[6] == 'a') && (p[7] == 'r') &&
        (p[8] == 'e') && (p[9] == 'n') && (p[10] == 't') && (p[11] == ':') && (p[12] == ' ')
    ) {
        return true;
    }

    return false;
}

struct callback_ctx {
    unsigned char *buf;
	u32 pos;
};

static int tp_match(u32 index, void *data)
{
    if (index >= (TRACE_BUF_SIZE-TRACE_PARENT_HEADER_LEN)) {
        return 1;
    }

	struct callback_ctx *ctx = data;    
    unsigned char *s = &(ctx->buf[index]);

    if (is_traceparent(s)) {
        ctx->pos = index;
        return 1;
    }

	return 0;
}


static __always_inline unsigned char *bpf_strstr_tp_loop(unsigned char *buf, int buf_len) {
    struct callback_ctx data = {
        .buf = buf,
        .pos = 0
    };

    u32 nr_loops = (u32)buf_len;

	bpf_loop(nr_loops, tp_match, &data, 0);

    if (data.pos) {
        u32 pos = (data.pos > (TRACE_BUF_SIZE-TRACE_PARENT_HEADER_LEN)) ? 0 : data.pos;
        return &(buf[pos]);
    }

    return 0;
}

#endif