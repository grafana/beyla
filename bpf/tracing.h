#ifndef TRACING_H
#define TRACING_H
#include "vmlinux.h"
#include "trace_util.h"

#define TRACE_ID_SIZE_BYTES 16
#define SPAN_ID_SIZE_BYTES   8
#define FLAGS_SIZE_BYTES     1
#define TRACE_ID_CHAR_LEN   32
#define SPAN_ID_CHAR_LEN    16
#define FLAGS_CHAR_LEN       2
#define TP_MAX_VAL_LENGTH   55
#define TP_MAX_KEY_LENGTH   11

typedef struct tp_info {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    unsigned char parent_id[SPAN_ID_SIZE_BYTES];
    u8  flags;
} tp_info_t;

static __always_inline void make_tp_string(unsigned char *buf, tp_info_t *tp) {
    // Version
    *buf++ = '0'; *buf++ = '0'; *buf++ = '-';

    // TraceID
    encode_hex(buf, tp->trace_id, TRACE_ID_SIZE_BYTES);
    buf += TRACE_ID_CHAR_LEN;
    *buf++ = '-';

    // SpanID
    encode_hex(buf, tp->span_id, SPAN_ID_SIZE_BYTES);
    buf += SPAN_ID_CHAR_LEN;
    *buf++ = '-';

    // Flags
    *buf++ = '0'; *buf = (tp->flags == 0) ? '0' : '1';
}

#endif