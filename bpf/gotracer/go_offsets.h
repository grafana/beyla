#pragma once

#include <bpfcore/utils.h>

#include <pid/pid_helpers.h>

#define MAX_GO_PROGRAMS 10000 // Max 10,000 go programs tracked

// To be Injected from the user space during the eBPF program load & initialization
typedef enum {
    // go common
    _conn_fd_pos = 1, // start at 1, must match what's in structmembers.go
    _fd_laddr_pos,
    _fd_raddr_pos,
    _tcp_addr_port_ptr_pos,
    _tcp_addr_ip_ptr_pos,
    // http
    _url_ptr_pos,
    _path_ptr_pos,
    _host_ptr_pos,
    _scheme_ptr_pos,
    _method_ptr_pos,
    _status_code_ptr_pos,
    _response_length_ptr_pos,
    _content_length_ptr_pos,
    _req_header_ptr_pos,
    _io_writer_buf_ptr_pos,
    _io_writer_n_pos,
    _cc_next_stream_id_pos,
    _cc_next_stream_id_vendored_pos,
    _cc_framer_pos,
    _cc_framer_vendored_pos,
    _framer_w_pos,
    _pc_conn_pos,
    _pc_tls_pos,
    _net_conn_pos,
    _cc_tconn_pos,
    _cc_tconn_vendored_pos,
    _sc_conn_pos,
    _c_rwc_pos,
    _c_tls_pos,
    // grpc
    _grpc_stream_st_ptr_pos,
    _grpc_stream_method_ptr_pos,
    _grpc_status_s_pos,
    _grpc_status_code_ptr_pos,
    _meta_headers_frame_fields_ptr_pos,
    _value_context_val_ptr_pos,
    _grpc_st_conn_pos,
    _grpc_t_conn_pos,
    _grpc_t_scheme_pos,
    _grpc_transport_stream_id_pos,
    _grpc_transport_buf_writer_buf_pos,
    _grpc_transport_buf_writer_offset_pos,
    _grpc_transport_buf_writer_conn_pos,
    // redis
    _redis_conn_bw_pos,
    // kafka go
    _kafka_go_writer_topic_pos,
    _kafka_go_protocol_conn_pos,
    _kafka_go_reader_topic_pos,
    // kafka sarama
    _sarama_broker_corr_id_pos,
    _sarama_response_corr_id_pos,
    _sarama_broker_conn_pos,
    _sarama_bufconn_conn_pos,
    // grpc versioning
    _grpc_one_six_zero,
    _grpc_one_six_nine,
    // grpc 1.69
    _grpc_server_stream_stream,
    _grpc_server_stream_st_ptr_pos,
    _grpc_client_stream_stream,
    _last_go_offset,
} go_offset_const;

typedef struct go_offset_t {
    go_offset_const v;
} go_offset;

typedef struct off_table {
    u64 table[_last_go_offset];
} off_table_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);           // key: upper 32 bit is PID, lower 32 bit is the offset
    __type(value, off_table_t); // the offset table
    __uint(max_entries, MAX_GO_PROGRAMS);
} go_offsets_map SEC(".maps");

static __always_inline off_table_t *get_offsets_table() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 ino = (u64)BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);
    return (off_table_t *)bpf_map_lookup_elem(&go_offsets_map, &ino);
}

static __always_inline u64 go_offset_of(off_table_t *ot, go_offset off) {
    if (ot && off.v < _last_go_offset) {
        return ot->table[off.v];
    }

    return -1;
}
