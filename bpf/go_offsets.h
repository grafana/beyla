#ifndef GO_OFFSETS_H
#define GO_OFFSETS_H

#include "utils.h"
#include "pid_types.h"

#define MAX_GO_PROGRAMS 10000 // Max 10,000 go programs tracked

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64); // key: upper 32 bit is PID, lower 32 bit is the offset
    __type(value, u64); // the offset
    __uint(max_entries, MAX_GO_PROGRAMS);
} go_offsets_map SEC(".maps");

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
    _method_ptr_pos,
    _status_code_ptr_pos,
    _content_length_ptr_pos,
    _req_header_ptr_pos,
    _io_writer_buf_ptr_pos,
    _io_writer_n_pos,
    _cc_next_stream_id_pos,
    _framer_w_pos,
    _pc_conn_pos,
    _pc_tls_pos,
    _net_conn_pos,
    _cc_tconn_pos,
    _sc_conn_pos,
    _c_rwc_pos,
    _c_tls_pos,
    // grpc
    _grpc_stream_st_ptr_pos,
    _grpc_stream_method_ptr_pos,
    _grpc_status_s_pos,
    _grpc_status_code_ptr_pos,
    _grpc_stream_ctx_ptr_pos,
    _value_context_val_ptr_pos,
    _grpc_st_conn_pos,
    _grpc_t_conn_pos,
    _grpc_t_scheme_pos,
    _http2_client_next_id_pos,
    _grpc_transport_buf_writer_buf_pos,
    _grpc_transport_buf_writer_offset_pos,
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
} go_offset;

static __always_inline u64 go_offset_of(u64 id, go_offset off) {
    u32 pid = pid_from_pid_tgid(id);
    u64 key = (u64)((u64)pid << 32) | off;
    
    u64 *val = (u64 *)bpf_map_lookup_elem(&go_offsets_map, &key);
    if (val) {
        return *val;
    }

    return -1;
}


#endif // GO_OFFSETS_H