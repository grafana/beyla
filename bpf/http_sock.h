#ifndef HTTP_SOCK_HELPERS
#define HTTP_SOCK_HELPERS

#include "common.h"
#include "bpf_helpers.h"
#include "http_types.h"

#define MIN_HTTP_SIZE 16 // GET / HTTP/1.1\r\n is the smallest valid request we can have

static __always_inline bool is_http(char *p, u32 len, bool *is_request) {
    if (len < MIN_HTTP_SIZE) {
        return false;
    }
	//HTTP
	if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
        *is_request = true;
		return true;
	}
	//GET
	if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T') && (p[3] == ' ') && (p[4] == '/')) {
		return true;
	}
	//POST
	if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T') && (p[4] == ' ') && (p[5] == '/')) {
		return true;
	}
	//PUT
	if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T') && (p[3] == ' ') && (p[4] == '/')) {
		return true;
	}
	//DELETE
	if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E') && (p[6] == ' ') && (p[7] == '/')) {
		return true;
	}
	//HEAD
	if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D') && (p[4] == ' ') && (p[5] == '/')) {
		return true;
	}
    // OPTIONS ? we don't care IMO

    return false;
}

static __always_inline void read_skb_bytes(const void *skb, u32 offset, unsigned char *buf, const u32 len) {
    u32 max = offset + len;
    int b = 0;
    for (; b < (FULL_BUF_SIZE/BUF_COPY_BLOCK_SIZE); b++) {
        if ((offset + (BUF_COPY_BLOCK_SIZE - 1)) >= max) {
            break;
        }
        bpf_skb_load_bytes(skb, offset, (void *)(&buf[b * BUF_COPY_BLOCK_SIZE]), BUF_COPY_BLOCK_SIZE);
        offset += BUF_COPY_BLOCK_SIZE;
    }

    if ((b * BUF_COPY_BLOCK_SIZE) >= len) {
        return;
    }

    // This code is messy to make sure the eBPF verifier is happy. I had to cast to signed 64bit.
    s64 remainder = (s64)max - (s64)offset;

    if (remainder <= 0) {
        return;
    }

    int tmp = (remainder < (BUF_COPY_BLOCK_SIZE - 1)) ? remainder : (BUF_COPY_BLOCK_SIZE - 1);
    int tmp1 = (len < (b * BUF_COPY_BLOCK_SIZE)) ? 0 : len - (b * BUF_COPY_BLOCK_SIZE);

    if (tmp <= tmp1) {
        bpf_skb_load_bytes(skb, offset, (void *)(&buf[b * BUF_COPY_BLOCK_SIZE]), tmp);
    }
}

#endif