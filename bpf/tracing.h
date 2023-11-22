#ifndef TRACING_H
#define TRACING_H
#include "vmlinux.h"

#define TRACE_ID_SIZE_BYTES 16
#define SPAN_ID_SIZE_BYTES   8
#define TRACE_ID_CHAR_LEN   32
#define SPAN_ID_CHAR_LEN    16
#define TP_MAX_VAL_LENGTH   55

typedef struct tp_info {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    unsigned char parent_id[SPAN_ID_SIZE_BYTES];
    u64 epoch;
} tp_info_t;

#endif