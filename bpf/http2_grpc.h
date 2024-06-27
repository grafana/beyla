#ifndef HTTP2_GRPC_HELPERS
#define HTTP2_GRPC_HELPERS

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_builtins.h"
#include "bpf_endian.h"
#include "http_types.h"

#define HTTP2_GRPC_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

#define FRAME_HEADER_LEN 9

#define FLAG_DATA_END_STREAM 0x1

typedef enum {
	FrameData         = 0x0,
	FrameHeaders      = 0x1,
	FramePriority     = 0x2,
	FrameRSTStream    = 0x3,
	FrameSettings     = 0x4,
	FramePushPromise  = 0x5,
	FramePing         = 0x6,
	FrameGoAway       = 0x7,
	FrameWindowUpdate = 0x8,
	FrameContinuation = 0x9,
} __attribute__((packed)) http2_frame_type_t;

typedef struct frame_header {
    u32 length:24;
    http2_frame_type_t type;
    u8 flags;
    u8 __ignore:1;
    u32 stream_id:31;
} __attribute__((packed)) frame_header_t;

static __always_inline u8 read_http2_grpc_frame_header(frame_header_t *frame, unsigned char *p, u32 len) {
    if (len < FRAME_HEADER_LEN) {
        return 0;
    }

    *frame = *((frame_header_t *)p);
    if (!frame->length || frame->type > FrameContinuation) {
        return 0;
    }

    frame->length = bpf_ntohl(frame->length << 8);
    frame->stream_id = bpf_ntohl(frame->stream_id << 1);

    return 1;
}

static __always_inline u8 is_settings_frame(unsigned char *p, u32 len) {
    frame_header_t frame = {0};

    if (!read_http2_grpc_frame_header(&frame, p, len)) {
        return 0;
    }

    return frame.type == FrameSettings && !frame.stream_id;
}

static __always_inline u8 is_headers_frame(frame_header_t *frame) {
    return frame->type == FrameHeaders && frame->stream_id;
}

static __always_inline u8 has_preface(unsigned char *p, u32 len) {
    if (len < MIN_HTTP2_SIZE) {
        return 0;
    }

    return !__bpf_memcmp(p, HTTP2_GRPC_PREFACE, MIN_HTTP2_SIZE);
}

static __always_inline u8 is_http2_or_grpc(unsigned char *p, u32 len) {
    return has_preface(p, len) || is_settings_frame(p, len);
}

static __always_inline u8 http_grpc_stream_ended(frame_header_t *frame) {
    return is_headers_frame(frame) && ((frame->flags & FLAG_DATA_END_STREAM) == FLAG_DATA_END_STREAM);
}

static __always_inline u8 is_invalid_frame(frame_header_t *frame) {
    return frame->length == 0 && frame->type == FrameData;
}

static __always_inline u8 is_data_frame(frame_header_t *frame) {
    return frame->length && frame->type == FrameData;
}

static __always_inline u8 is_flags_only_frame(frame_header_t *frame) {
    return frame->length <= 2;
}

#endif // HTTP2_GRPC_HELPERS