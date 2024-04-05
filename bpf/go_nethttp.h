// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef GO_NETHTTP_H
#define GO_NETHTTP_H

#include "utils.h"

// To be Injected from the user space during the eBPF program load & initialization

volatile const u64 url_ptr_pos;
volatile const u64 path_ptr_pos;
volatile const u64 method_ptr_pos;
volatile const u64 status_ptr_pos;
volatile const u64 status_code_ptr_pos;
volatile const u64 remoteaddr_ptr_pos;
volatile const u64 host_ptr_pos;
volatile const u64 content_length_ptr_pos;
volatile const u64 resp_req_pos;
volatile const u64 req_header_ptr_pos;
volatile const u64 io_writer_buf_ptr_pos;
volatile const u64 io_writer_n_pos;
volatile const u64 rws_req_pos;
volatile const u64 rws_status_pos;
volatile const u64 cc_next_stream_id_pos;
volatile const u64 framer_w_pos;

volatile const u64 c_rwc_pos;
volatile const u64 pc_conn_pos;
volatile const u64 rwc_conn_pos;
volatile const u64 conn_fd_pos;
volatile const u64 fd_laddr_pos;
volatile const u64 fd_raddr_pos;
volatile const u64 tcp_addr_port_ptr_pos;
volatile const u64 tcp_addr_ip_ptr_pos;

#endif
