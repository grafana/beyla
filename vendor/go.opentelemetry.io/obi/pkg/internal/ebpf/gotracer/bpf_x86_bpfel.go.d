pkg/internal/ebpf/gotracer/bpf_x86_bpfel.go: \
 bpf/gotracer/gotracer.c \
 bpf/gotracer/go_runtime.c \
 bpf/bpfcore/utils.h \
 bpf/bpfcore/vmlinux.h \
 bpf/bpfcore/vmlinux_amd64.h \
 bpf/bpfcore/bpf_tracing.h \
 bpf/bpfcore/bpf_helpers.h \
 bpf/bpfcore/bpf_helper_defs.h \
 bpf/common/ringbuf.h \
 bpf/common/event_defs.h \
 bpf/common/pin_internal.h \
 bpf/gotracer/go_common.h \
 bpf/common/go_addr_key.h \
 bpf/common/map_sizing.h \
 bpf/common/strings.h \
 bpf/common/trace_util.h \
 bpf/common/algorithm.h \
 bpf/common/globals.h \
 bpf/common/http_buf_size.h \
 bpf/common/tracing.h \
 bpf/common/http_types.h \
 bpf/common/connection_info.h \
 bpf/common/egress_key.h \
 bpf/common/fd_info.h \
 bpf/pid/types/pid_key.h \
 bpf/pid/pid_helpers.h \
 bpf/bpfcore/bpf_core_read.h \
 bpf/pid/types/pid_info.h \
 bpf/common/protocol_defs.h \
 bpf/logger/bpf_dbg.h \
 bpf/common/http_info.h \
 bpf/common/event_source.h \
 bpf/common/tp_info.h \
 bpf/common/lw_thread.h \
 bpf/maps/trace_map.h \
 bpf/common/trace_map_key.h \
 bpf/gotracer/go_offsets.h \
 bpf/gotracer/go_constants.h \
 bpf/gotracer/maps/handled_by_go.h \
 bpf/maps/incoming_trace_map.h \
 bpf/gotracer/maps/grpc.h \
 bpf/gotracer/types/grpc.h \
 bpf/gotracer/types/stream_key.h \
 bpf/gotracer/maps/kafka.h \
 bpf/common/common.h \
 bpf/gotracer/types/kafka.h \
 bpf/gotracer/maps/mongo.h \
 bpf/gotracer/maps/nethttp.h \
 bpf/gotracer/types/nethttp.h \
 bpf/gotracer/maps/redis.h \
 bpf/gotracer/maps/runtime.h \
 bpf/shared/obi_ctx.h \
 bpf/bpfcore/bpf_builtins.h \
 bpf/bpfcore/compiler.h \
 bpf/gotracer/go_net.c \
 bpf/generictracer/k_tracer_defs.h \
 bpf/common/protocol_http_helpers.h \
 bpf/maps/ongoing_http.h \
 bpf/generictracer/k_tracer_tailcall.h \
 bpf/generictracer/protocol_common.h \
 bpf/common/iov_iter.h \
 bpf/common/large_buffers.h \
 bpf/common/scratch_mem.h \
 bpf/common/sock_port_ns.h \
 bpf/generictracer/maps/connection_meta_mem.h \
 bpf/generictracer/maps/iovec_mem.h \
 bpf/generictracer/maps/listening_ports.h \
 bpf/generictracer/maps/protocol_args_mem.h \
 bpf/generictracer/maps/protocol_cache.h \
 bpf/maps/outgoing_trace_map.h \
 bpf/gotracer/types/net_args.h \
 bpf/gotracer/maps/ongoing_fd_reads.h \
 bpf/gotracer/maps/ongoing_ssl_ops.h \
 bpf/gotracer/go_net_common.h \
 bpf/maps/ongoing_tcp_req.h \
 bpf/maps/ongoing_http2_connections.h \
 bpf/generictracer/types/http2_conn_info_data.h \
 bpf/gotracer/go_net_tls.c \
 bpf/gotracer/go_nethttp.c \
 bpf/common/trace_helpers.h \
 bpf/gotracer/go_str.h \
 bpf/maps/go_ongoing_http.h \
 bpf/maps/go_ongoing_http_client_requests.h \
 bpf/common/http_func_invocation.h \
 bpf/maps/tp_char_buf_mem.h \
 bpf/gotracer/go_sql.c \
 bpf/maps/go_sql.h \
 bpf/gotracer/go_grpc.c \
 bpf/common/go_grpc_client_conn.h \
 bpf/maps/go_grpc_client_conns.h \
 bpf/gotracer/go_redis.c \
 bpf/gotracer/go_kafka_go.c \
 bpf/gotracer/go_sarama.c \
 bpf/gotracer/go_sdk.c \
 bpf/gotracer/types/otel_types.h \
 bpf/gotracer/go_mongo.c \
 bpf/generictracer/protocol_handler.c \
 bpf/common/tc_common.h \
 bpf/generictracer/protocol_http.h \
 bpf/common/runtime.h \
 bpf/maps/active_unix_socks.h \
 bpf/common/trace_lifecycle.h \
 bpf/common/trace_key.h \
 bpf/maps/cp_support_connect_info.h \
 bpf/common/cp_support_data.h \
 bpf/maps/java_vt_threads.h \
 bpf/maps/server_traces.h \
 bpf/common/trace_parent.h \
 bpf/common/python_task.h \
 bpf/maps/python_context_task.h \
 bpf/maps/python_task_state.h \
 bpf/maps/clone_map.h \
 bpf/maps/fd_map.h \
 bpf/maps/fd_to_connection.h \
 bpf/common/fd_key.h \
 bpf/maps/java_tasks.h \
 bpf/maps/nginx_upstream.h \
 bpf/maps/nodejs_fd_map.h \
 bpf/maps/puma_tasks.h \
 bpf/common/puma_task_id.h \
 bpf/maps/python_thread_state.h \
 bpf/maps/tp_info_mem.h \
 bpf/common/tracked_connection.h \
 bpf/generictracer/maps/http_info_mem.h \
 bpf/maps/active_ssl_connections.h \
 bpf/maps/connection_tracker.h \
 bpf/generictracer/protocol_http2.h \
 bpf/common/h2_defs.h \
 bpf/generictracer/http2_grpc.h \
 bpf/bpfcore/bpf_endian.h \
 bpf/generictracer/maps/grpc_frames_ctx_mem.h \
 bpf/generictracer/types/grpc_frames_ctx.h \
 bpf/generictracer/maps/http2_info_mem.h \
 bpf/generictracer/maps/ongoing_http2_grpc.h \
 bpf/generictracer/protocol_kafka.h \
 bpf/generictracer/protocol_mysql.h \
 bpf/common/sql.h \
 bpf/generictracer/protocol_postgres.h \
 bpf/generictracer/protocol_sunrpc.h \
 bpf/generictracer/protocol_tcp.h \
 bpf/generictracer/failed_connect.h \
 bpf/generictracer/protocol_mssql.h \
 bpf/generictracer/maps/tcp_req_mem.h

bpf/gotracer/go_runtime.c:

bpf/bpfcore/utils.h:

bpf/bpfcore/vmlinux.h:

bpf/bpfcore/vmlinux_amd64.h:

bpf/bpfcore/bpf_tracing.h:

bpf/bpfcore/bpf_helpers.h:

bpf/bpfcore/bpf_helper_defs.h:

bpf/common/ringbuf.h:

bpf/common/event_defs.h:

bpf/common/pin_internal.h:

bpf/gotracer/go_common.h:

bpf/common/go_addr_key.h:

bpf/common/map_sizing.h:

bpf/common/strings.h:

bpf/common/trace_util.h:

bpf/common/algorithm.h:

bpf/common/globals.h:

bpf/common/http_buf_size.h:

bpf/common/tracing.h:

bpf/common/http_types.h:

bpf/common/connection_info.h:

bpf/common/egress_key.h:

bpf/common/fd_info.h:

bpf/pid/types/pid_key.h:

bpf/pid/pid_helpers.h:

bpf/bpfcore/bpf_core_read.h:

bpf/pid/types/pid_info.h:

bpf/common/protocol_defs.h:

bpf/logger/bpf_dbg.h:

bpf/common/http_info.h:

bpf/common/event_source.h:

bpf/common/tp_info.h:

bpf/common/lw_thread.h:

bpf/maps/trace_map.h:

bpf/common/trace_map_key.h:

bpf/gotracer/go_offsets.h:

bpf/gotracer/go_constants.h:

bpf/gotracer/maps/handled_by_go.h:

bpf/maps/incoming_trace_map.h:

bpf/gotracer/maps/grpc.h:

bpf/gotracer/types/grpc.h:

bpf/gotracer/types/stream_key.h:

bpf/gotracer/maps/kafka.h:

bpf/common/common.h:

bpf/gotracer/types/kafka.h:

bpf/gotracer/maps/mongo.h:

bpf/gotracer/maps/nethttp.h:

bpf/gotracer/types/nethttp.h:

bpf/gotracer/maps/redis.h:

bpf/gotracer/maps/runtime.h:

bpf/shared/obi_ctx.h:

bpf/bpfcore/bpf_builtins.h:

bpf/bpfcore/compiler.h:

bpf/gotracer/go_net.c:

bpf/generictracer/k_tracer_defs.h:

bpf/common/protocol_http_helpers.h:

bpf/maps/ongoing_http.h:

bpf/generictracer/k_tracer_tailcall.h:

bpf/generictracer/protocol_common.h:

bpf/common/iov_iter.h:

bpf/common/large_buffers.h:

bpf/common/scratch_mem.h:

bpf/common/sock_port_ns.h:

bpf/generictracer/maps/connection_meta_mem.h:

bpf/generictracer/maps/iovec_mem.h:

bpf/generictracer/maps/listening_ports.h:

bpf/generictracer/maps/protocol_args_mem.h:

bpf/generictracer/maps/protocol_cache.h:

bpf/maps/outgoing_trace_map.h:

bpf/gotracer/types/net_args.h:

bpf/gotracer/maps/ongoing_fd_reads.h:

bpf/gotracer/maps/ongoing_ssl_ops.h:

bpf/gotracer/go_net_common.h:

bpf/maps/ongoing_tcp_req.h:

bpf/maps/ongoing_http2_connections.h:

bpf/generictracer/types/http2_conn_info_data.h:

bpf/gotracer/go_net_tls.c:

bpf/gotracer/go_nethttp.c:

bpf/common/trace_helpers.h:

bpf/gotracer/go_str.h:

bpf/maps/go_ongoing_http.h:

bpf/maps/go_ongoing_http_client_requests.h:

bpf/common/http_func_invocation.h:

bpf/maps/tp_char_buf_mem.h:

bpf/gotracer/go_sql.c:

bpf/maps/go_sql.h:

bpf/gotracer/go_grpc.c:

bpf/common/go_grpc_client_conn.h:

bpf/maps/go_grpc_client_conns.h:

bpf/gotracer/go_redis.c:

bpf/gotracer/go_kafka_go.c:

bpf/gotracer/go_sarama.c:

bpf/gotracer/go_sdk.c:

bpf/gotracer/types/otel_types.h:

bpf/gotracer/go_mongo.c:

bpf/generictracer/protocol_handler.c:

bpf/common/tc_common.h:

bpf/generictracer/protocol_http.h:

bpf/common/runtime.h:

bpf/maps/active_unix_socks.h:

bpf/common/trace_lifecycle.h:

bpf/common/trace_key.h:

bpf/maps/cp_support_connect_info.h:

bpf/common/cp_support_data.h:

bpf/maps/java_vt_threads.h:

bpf/maps/server_traces.h:

bpf/common/trace_parent.h:

bpf/common/python_task.h:

bpf/maps/python_context_task.h:

bpf/maps/python_task_state.h:

bpf/maps/clone_map.h:

bpf/maps/fd_map.h:

bpf/maps/fd_to_connection.h:

bpf/common/fd_key.h:

bpf/maps/java_tasks.h:

bpf/maps/nginx_upstream.h:

bpf/maps/nodejs_fd_map.h:

bpf/maps/puma_tasks.h:

bpf/common/puma_task_id.h:

bpf/maps/python_thread_state.h:

bpf/maps/tp_info_mem.h:

bpf/common/tracked_connection.h:

bpf/generictracer/maps/http_info_mem.h:

bpf/maps/active_ssl_connections.h:

bpf/maps/connection_tracker.h:

bpf/generictracer/protocol_http2.h:

bpf/common/h2_defs.h:

bpf/generictracer/http2_grpc.h:

bpf/bpfcore/bpf_endian.h:

bpf/generictracer/maps/grpc_frames_ctx_mem.h:

bpf/generictracer/types/grpc_frames_ctx.h:

bpf/generictracer/maps/http2_info_mem.h:

bpf/generictracer/maps/ongoing_http2_grpc.h:

bpf/generictracer/protocol_kafka.h:

bpf/generictracer/protocol_mysql.h:

bpf/common/sql.h:

bpf/generictracer/protocol_postgres.h:

bpf/generictracer/protocol_sunrpc.h:

bpf/generictracer/protocol_tcp.h:

bpf/generictracer/failed_connect.h:

bpf/generictracer/protocol_mssql.h:

bpf/generictracer/maps/tcp_req_mem.h:

