#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

struct bpf_map_def SEC("maps") jump_table = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 8,
};

enum {
    k_tail_protocol_http = 0,
    k_tail_protocol_http2 = 1,
    k_tail_protocol_tcp = 2,
    k_tail_protocol_http2_grpc_frames = 3,
    k_tail_protocol_http2_grpc_handle_start_frame = 4,
    k_tail_protocol_http2_grpc_handle_end_frame = 5,
};
