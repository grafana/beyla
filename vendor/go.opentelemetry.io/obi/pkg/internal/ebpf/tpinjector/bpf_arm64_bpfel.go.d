pkg/internal/ebpf/tpinjector/bpf_arm64_bpfel.go: \
 bpf/tpinjector/tpinjector.c \
 bpf/bpfcore/vmlinux.h \
 bpf/bpfcore/vmlinux_arm64.h \
 bpf/bpfcore/bpf_builtins.h \
 bpf/bpfcore/bpf_helpers.h \
 bpf/bpfcore/bpf_helper_defs.h \
 bpf/bpfcore/compiler.h \
 bpf/bpfcore/bpf_endian.h \
 bpf/common/connection_info.h \
 bpf/common/egress_key.h \
 bpf/common/fd_info.h \
 bpf/bpfcore/utils.h \
 bpf/bpfcore/bpf_tracing.h \
 bpf/pid/types/pid_key.h \
 bpf/pid/pid_helpers.h \
 bpf/bpfcore/bpf_core_read.h \
 bpf/pid/types/pid_info.h \
 bpf/common/protocol_defs.h \
 bpf/logger/bpf_dbg.h \
 bpf/common/globals.h \
 bpf/common/pin_internal.h \
 bpf/common/event_defs.h \
 bpf/common/http_buf_size.h \
 bpf/common/http_types.h \
 bpf/common/http_info.h \
 bpf/common/tp_info.h \
 bpf/common/msg_buffer.h \
 bpf/common/protocol_http.h \
 bpf/maps/ongoing_http.h \
 bpf/common/map_sizing.h \
 bpf/common/protocol_http2.h \
 bpf/maps/ongoing_http2_connections.h \
 bpf/generictracer/types/http2_conn_info_data.h \
 bpf/common/protocol_tcp.h \
 bpf/maps/ongoing_tcp_req.h \
 bpf/common/common.h \
 bpf/common/scratch_mem.h \
 bpf/common/ssl_connection.h \
 bpf/maps/active_ssl_connections.h \
 bpf/common/tc_common.h \
 bpf/common/trace_parent.h \
 bpf/common/runtime.h \
 bpf/maps/active_unix_socks.h \
 bpf/common/trace_helpers.h \
 bpf/common/trace_util.h \
 bpf/common/tracing.h \
 bpf/maps/trace_map.h \
 bpf/common/trace_map_key.h \
 bpf/maps/clone_map.h \
 bpf/maps/cp_support_connect_info.h \
 bpf/common/cp_support_data.h \
 bpf/common/trace_key.h \
 bpf/maps/fd_map.h \
 bpf/maps/fd_to_connection.h \
 bpf/common/fd_key.h \
 bpf/maps/java_tasks.h \
 bpf/maps/nginx_upstream.h \
 bpf/maps/nodejs_fd_map.h \
 bpf/maps/puma_tasks.h \
 bpf/common/puma_task_id.h \
 bpf/maps/server_traces.h \
 bpf/maps/incoming_trace_map.h \
 bpf/maps/msg_buffers.h \
 bpf/maps/outgoing_trace_map.h \
 bpf/maps/sock_dir.h \
 bpf/maps/tp_info_mem.h \
 bpf/pid/pid.h \
 bpf/pid/maps/pid_cache.h \
 bpf/pid/maps/map_sizing.h \
 bpf/pid/maps/valid_pids.h \
 bpf/pid/types/pid_data.h \
 bpf/tpinjector/maps/sk_tp_info_pid_map.h

bpf/bpfcore/vmlinux.h:

bpf/bpfcore/vmlinux_arm64.h:

bpf/bpfcore/bpf_builtins.h:

bpf/bpfcore/bpf_helpers.h:

bpf/bpfcore/bpf_helper_defs.h:

bpf/bpfcore/compiler.h:

bpf/bpfcore/bpf_endian.h:

bpf/common/connection_info.h:

bpf/common/egress_key.h:

bpf/common/fd_info.h:

bpf/bpfcore/utils.h:

bpf/bpfcore/bpf_tracing.h:

bpf/pid/types/pid_key.h:

bpf/pid/pid_helpers.h:

bpf/bpfcore/bpf_core_read.h:

bpf/pid/types/pid_info.h:

bpf/common/protocol_defs.h:

bpf/logger/bpf_dbg.h:

bpf/common/globals.h:

bpf/common/pin_internal.h:

bpf/common/event_defs.h:

bpf/common/http_buf_size.h:

bpf/common/http_types.h:

bpf/common/http_info.h:

bpf/common/tp_info.h:

bpf/common/msg_buffer.h:

bpf/common/protocol_http.h:

bpf/maps/ongoing_http.h:

bpf/common/map_sizing.h:

bpf/common/protocol_http2.h:

bpf/maps/ongoing_http2_connections.h:

bpf/generictracer/types/http2_conn_info_data.h:

bpf/common/protocol_tcp.h:

bpf/maps/ongoing_tcp_req.h:

bpf/common/common.h:

bpf/common/scratch_mem.h:

bpf/common/ssl_connection.h:

bpf/maps/active_ssl_connections.h:

bpf/common/tc_common.h:

bpf/common/trace_parent.h:

bpf/common/runtime.h:

bpf/maps/active_unix_socks.h:

bpf/common/trace_helpers.h:

bpf/common/trace_util.h:

bpf/common/tracing.h:

bpf/maps/trace_map.h:

bpf/common/trace_map_key.h:

bpf/maps/clone_map.h:

bpf/maps/cp_support_connect_info.h:

bpf/common/cp_support_data.h:

bpf/common/trace_key.h:

bpf/maps/fd_map.h:

bpf/maps/fd_to_connection.h:

bpf/common/fd_key.h:

bpf/maps/java_tasks.h:

bpf/maps/nginx_upstream.h:

bpf/maps/nodejs_fd_map.h:

bpf/maps/puma_tasks.h:

bpf/common/puma_task_id.h:

bpf/maps/server_traces.h:

bpf/maps/incoming_trace_map.h:

bpf/maps/msg_buffers.h:

bpf/maps/outgoing_trace_map.h:

bpf/maps/sock_dir.h:

bpf/maps/tp_info_mem.h:

bpf/pid/pid.h:

bpf/pid/maps/pid_cache.h:

bpf/pid/maps/map_sizing.h:

bpf/pid/maps/valid_pids.h:

bpf/pid/types/pid_data.h:

bpf/tpinjector/maps/sk_tp_info_pid_map.h:

