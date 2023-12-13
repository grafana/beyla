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

#include "pid.h"
#include "utils.h"
#include "go_str.h"
#include "go_byte_arr.h"
#include "bpf_dbg.h"
#include "go_common.h"
#include "go_traceparent.h"

typedef struct grpc_srv_func_invocation {
    u64 start_monotime_ns;
    u64 stream;
    tp_info_t tp;
} grpc_srv_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, u16);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_request_status SEC(".maps");

typedef struct grpc_client_func_invocation {
    u64 start_monotime_ns;
    u64 cc;
    u64 method;
    u64 method_len;
    tp_info_t tp;
    u64 flags;
} grpc_client_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, grpc_client_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_client_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, grpc_srv_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_server_requests SEC(".maps");

// Context propagation
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32); // key: stream id
    __type(value, void *); // pointer to the request goroutine
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_streams SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, grpc_client_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ongoing_grpc_header_writes SEC(".maps");


// To be Injected from the user space during the eBPF program load & initialization

volatile const u64 grpc_stream_st_ptr_pos;
volatile const u64 grpc_stream_method_ptr_pos;
volatile const u64 grpc_status_s_pos;
volatile const u64 grpc_status_code_ptr_pos;
volatile const u64 grpc_st_remoteaddr_ptr_pos;
volatile const u64 grpc_st_localaddr_ptr_pos;
volatile const u64 tcp_addr_port_ptr_pos;
volatile const u64 tcp_addr_ip_ptr_pos;
volatile const u64 grpc_client_target_ptr_pos;
volatile const u64 grpc_stream_ctx_ptr_pos;
volatile const u64 value_context_val_ptr_pos;

// Context propagation
volatile const u64 http2_client_next_id_pos;
volatile const u64 hpack_encoder_w_pos;

#define GRPC_ENCODED_HEADER_LEN 69 // 1 + 1 + TP_MAX_KEY_LENGTH + 1 + TP_MAX_VAL_LENGTH = type byte + len_as_byte("traceparent") + strlen(traceparent) + len_as_byte(TP_MAX_VAL_LENGTH) + TP_MAX_VAL_LENGTH 

SEC("uprobe/server_handleStream")
int uprobe_server_handleStream(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/server_handleStream === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *stream_ptr = GO_PARAM4(ctx);

    grpc_srv_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .stream = (u64)stream_ptr,
        .tp = {0}
    };

    if (stream_ptr) {
        void *ctx_ptr = 0;
        // Read the embedded context object ptr
        bpf_probe_read(&ctx_ptr, sizeof(ctx_ptr), (void *)(stream_ptr + grpc_stream_ctx_ptr_pos + sizeof(void *)));

        if (ctx_ptr) {
            server_trace_parent(goroutine_addr, &invocation.tp, (void *)(ctx_ptr + value_context_val_ptr_pos + sizeof(void *)));
        }
    }

    if (bpf_map_update_elem(&ongoing_grpc_server_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update grpc map element");
    }

    return 0;
}

SEC("uprobe/server_handleStream")
int uprobe_server_handleStream_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/server_handleStream return === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    grpc_srv_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_grpc_server_requests, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_grpc_server_requests, &goroutine_addr);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read grpc invocation metadata");
        return 0;
    }

    u16 *status = bpf_map_lookup_elem(&ongoing_grpc_request_status, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_grpc_request_status, &goroutine_addr);
    if (status == NULL) {
        bpf_dbg_printk("can't read grpc invocation status");
        return 0;
    }

    void *stream_ptr = (void *)invocation->stream;
    bpf_dbg_printk("stream_ptr %lx, method pos %lx", stream_ptr, grpc_stream_method_ptr_pos);

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        return 0;
    }
    task_pid(&trace->pid);
    trace->type = EVENT_GRPC_REQUEST;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->status = *status;

    goroutine_metadata *g_metadata = bpf_map_lookup_elem(&ongoing_goroutines, &goroutine_addr);
    if (g_metadata) {
        trace->go_start_monotime_ns = g_metadata->timestamp;
        bpf_map_delete_elem(&ongoing_goroutines, &goroutine_addr);
    } else {
        trace->go_start_monotime_ns = invocation->start_monotime_ns;
    }

    // Get method from transport.Stream.Method
    if (!read_go_str("grpc method", stream_ptr, grpc_stream_method_ptr_pos, &trace->path, sizeof(trace->path))) {
        bpf_printk("can't read grpc transport.Stream.Method");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    void *st_ptr = 0;
    // Read the embedded object ptr
    bpf_probe_read(&st_ptr, sizeof(st_ptr), (void *)(stream_ptr + grpc_stream_st_ptr_pos + sizeof(void *)));

    if (st_ptr) {
        void *peer_ptr = 0; 
        bpf_probe_read(&peer_ptr, sizeof(peer_ptr), (void *)(st_ptr + grpc_st_remoteaddr_ptr_pos + sizeof(void *)));

        if (peer_ptr) {
            u64 remote_addr_len = 0;
            if (!read_go_byte_arr("grpc peer ptr", peer_ptr, tcp_addr_ip_ptr_pos, &trace->remote_addr, &remote_addr_len, sizeof(trace->remote_addr))) {
                bpf_printk("can't read grpc peer ptr");
                bpf_ringbuf_discard(trace, 0);
                return 0;
            }
            trace->remote_addr_len = remote_addr_len;
        }

        void *host_ptr = 0;
        bpf_probe_read(&host_ptr, sizeof(host_ptr), (void *)(st_ptr + grpc_st_localaddr_ptr_pos + sizeof(void *)));

        if (host_ptr) {
            u64 host_len = 0;

            if (!read_go_byte_arr("grpc host ptr", host_ptr, tcp_addr_ip_ptr_pos, &trace->host, &host_len,  sizeof(trace->host))) {
                bpf_printk("can't read grpc host ptr");
                bpf_ringbuf_discard(trace, 0);
                return 0;
            }
            trace->host_len = host_len;

            bpf_probe_read(&trace->host_port, sizeof(trace->host_port), (void *)(host_ptr + tcp_addr_port_ptr_pos));
        }
    }

    trace->tp = invocation->tp;

    trace->end_monotime_ns = bpf_ktime_get_ns();
    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

    return 0;
}

SEC("uprobe/transport_writeStatus")
int uprobe_transport_writeStatus(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/transport_writeStatus === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *status_ptr = GO_PARAM3(ctx);
    bpf_dbg_printk("status_ptr %lx", status_ptr);

    if (status_ptr != NULL) {
        void *s_ptr;
        bpf_probe_read(&s_ptr, sizeof(s_ptr), (void *)(status_ptr + grpc_status_s_pos));

        bpf_dbg_printk("s_ptr %lx", s_ptr);

        if (s_ptr != NULL) {
            u16 status = -1;
            bpf_probe_read(&status, sizeof(status), (void *)(s_ptr + grpc_status_code_ptr_pos));
            bpf_dbg_printk("status code %d", status);
            bpf_map_update_elem(&ongoing_grpc_request_status, &goroutine_addr, &status, BPF_ANY);
        }
    }

    return 0;
}

/* GRPC client */
static __always_inline void clientConnStart(void *goroutine_addr, void *cc_ptr, void *ctx_ptr, void *method_ptr, void *method_len) {
    grpc_client_func_invocation_t invocation = {
        .start_monotime_ns = bpf_ktime_get_ns(),
        .cc = (u64)cc_ptr,
        .method = (u64)method_ptr,
        .method_len = (u64)method_len,
        .tp = {0},
        .flags = 0,
    };

    if (ctx_ptr) {
        void *val_ptr = 0;
        // Read the embedded val object ptr from ctx if there's one
        bpf_probe_read(&val_ptr, sizeof(val_ptr), (void *)(ctx_ptr + value_context_val_ptr_pos + sizeof(void *)));

        invocation.flags = client_trace_parent(goroutine_addr, &invocation.tp, (void *)(val_ptr));
    } else {
        // it's OK sending empty tp for a client, the userspace id generator will make random trace_id, span_id
        bpf_dbg_printk("No ctx_ptr %llx", ctx_ptr);
    }

    // Write event
    if (bpf_map_update_elem(&ongoing_grpc_client_requests, &goroutine_addr, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update grpc client map element");
    }
}

SEC("uprobe/ClientConn_Invoke")
int uprobe_ClientConn_Invoke(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc ClientConn.Invoke === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *cc_ptr = GO_PARAM1(ctx);
    void *ctx_ptr = GO_PARAM3(ctx);
    void *method_ptr = GO_PARAM4(ctx);
    void *method_len = GO_PARAM5(ctx);

    clientConnStart(goroutine_addr, cc_ptr, ctx_ptr, method_ptr, method_len);

    return 0;
}

// Same as ClientConn_Invoke, registers for the method are offset by one
SEC("uprobe/ClientConn_NewStream")
int uprobe_ClientConn_NewStream(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc ClientConn.NewStream === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *cc_ptr = GO_PARAM1(ctx);
    void *ctx_ptr = GO_PARAM3(ctx);
    void *method_ptr = GO_PARAM5(ctx);
    void *method_len = GO_PARAM6(ctx);

    clientConnStart(goroutine_addr, cc_ptr, ctx_ptr, method_ptr, method_len);

    return 0;
}

SEC("uprobe/ClientConn_Invoke")
int uprobe_ClientConn_Invoke_return(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc grpc ClientConn.Invoke/ClientConn.NewStream return === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    grpc_client_func_invocation_t *invocation =
        bpf_map_lookup_elem(&ongoing_grpc_client_requests, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_grpc_client_requests, &goroutine_addr);

    if (invocation == NULL) {
        bpf_dbg_printk("can't read grpc client invocation metadata");
        return 0;
    }

    http_request_trace *trace = bpf_ringbuf_reserve(&events, sizeof(http_request_trace), 0);
    if (!trace) {
        bpf_dbg_printk("can't reserve space in the ringbuffer");
        return 0;
    }

    task_pid(&trace->pid);
    trace->type = EVENT_GRPC_CLIENT;
    trace->start_monotime_ns = invocation->start_monotime_ns;
    trace->go_start_monotime_ns = invocation->start_monotime_ns;
    trace->end_monotime_ns = bpf_ktime_get_ns();

    // Read arguments from the original set of registers

    // Get client request value pointers
    void *cc_ptr = (void *)invocation->cc;
    void *method_ptr = (void *)invocation->method;
    void *method_len = (void *)invocation->method_len;
    void *err = (void *)GO_PARAM1(ctx);

    bpf_dbg_printk("method ptr = %lx, method_len = %d", method_ptr, method_len);

    // Get method from the incoming call arguments
    if (!read_go_str_n("method", method_ptr, (u64)method_len, &trace->path, sizeof(trace->path))) {
        bpf_printk("can't read grpc client method");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    // Get the host information of the remote
    if (!read_go_str("host", cc_ptr, grpc_client_target_ptr_pos, &trace->host, sizeof(trace->host))) {
        bpf_printk("can't read http Request.Host");
        bpf_ringbuf_discard(trace, 0);
        return 0;
    }

    trace->tp = invocation->tp;

    trace->status = (err) ? 2 : 0; // Getting the gRPC client status is complex, if there's an error we set Code.Unknown = 2

    // submit the completed trace via ringbuffer
    bpf_ringbuf_submit(trace, get_flags());

    return 0;
}

// The gRPC client stream is written on another goroutine in transport loopyWriter (controlbuf.go).
// We extract the stream ID when it's just created and make a mapping of it to our goroutine that's executing ClientConn.Invoke.
SEC("uprobe/transport_http2Client_NewStream")
int uprobe_transport_http2Client_NewStream(struct pt_regs *ctx) {
#ifndef NO_HEADER_PROPAGATION
    bpf_dbg_printk("=== uprobe/proc transport.(*http2Client).NewStream === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    void *t_ptr = GO_PARAM1(ctx);

    bpf_dbg_printk("goroutine_addr %lx, t_ptr %llx", goroutine_addr, t_ptr);

    if (t_ptr) {
        u32 next_id = 0;
        // Read the next stream id from the httpClient
        bpf_probe_read(&next_id, sizeof(next_id), (void *)(t_ptr + http2_client_next_id_pos));

        bpf_dbg_printk("next_id %d", next_id);
        // This map is an LRU map, we can't be sure that all created streams are going to be
        // seen later by writeHeader to clean up this mapping.
        bpf_map_update_elem(&ongoing_streams, &next_id, &goroutine_addr, BPF_ANY);
    }
    
#endif    
    return 0;
}

// LoopyWriter is about to write the headers, we lookup to see if this StreamID (first argument after the receiver)
// to see if it has a ClientConn.Invoke mapping. If we find one, we duplicate the invocation metadata on the loopyWriter
// goroutine.
SEC("uprobe/transport_loopyWriter_writeHeader")
int uprobe_transport_loopyWriter_writeHeader(struct pt_regs *ctx) {
#ifndef NO_HEADER_PROPAGATION
    bpf_dbg_printk("=== uprobe/proc transport.(*loopyWriter).writeHeader === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);    
    u64 stream_id = (u64)GO_PARAM2(ctx);

    bpf_dbg_printk("goroutine_addr %lx, stream_id %d", goroutine_addr, stream_id);

    if (stream_id) {
        void **invocation_go_ptr = bpf_map_lookup_elem(&ongoing_streams, &stream_id);
        bpf_map_delete_elem(&ongoing_streams, &stream_id);

        if (invocation_go_ptr) {
            void *invocation_go = *invocation_go_ptr;
            bpf_dbg_printk("invocation goroutine_addr %lx", invocation_go);

            grpc_client_func_invocation_t *invocation = bpf_map_lookup_elem(&ongoing_grpc_client_requests, &invocation_go);

            if (invocation && !invocation->flags) {
                bpf_dbg_printk("found invocation metadata %llx", invocation);

                grpc_client_func_invocation_t inv_save = *invocation;
                bpf_map_update_elem(&ongoing_grpc_header_writes, &goroutine_addr, &inv_save, BPF_ANY);
            }
        }
    }
#endif
    return 0;
}

SEC("uprobe/transport_loopyWriter_writeHeader_return")
int uprobe_transport_loopyWriter_writeHeader_return(struct pt_regs *ctx) {
#ifndef NO_HEADER_PROPAGATION
    bpf_dbg_printk("=== uprobe/proc transport.(*loopyWriter).writeHeader returns === ");
    void *goroutine_addr = GOROUTINE_PTR(ctx);
    // Delete the extra metadata just in case we didn't write the fields
    bpf_map_delete_elem(&ongoing_grpc_header_writes, &goroutine_addr);
#endif
    return 0;
}

// WriteField will insert the traceparent in an appropriate location. We look into
// all incoming headers, skip until we get past the protocol headers, e.g. :method and
// then we inject traceparent at the first opportunity.
// 
// This may not work for two reasons, although both are rare:
// - gRPC buffers are short and we need 69 characters of capacity in w.buf. It usually has 128, but it can be
//   as low as 64, in which case we can't add the traceparent. We can cut this 69 to 47 if we did Huffman encoding
//   but it's complicated to implement in eBPF, rounding, adding trailing padding and all.
// - There are no headers other than the protocol headers, in which case we'll never find a spot to insert the
//   traceparent header. (Theoretical situation)
SEC("uprobe/hpack_Encoder_WriteField")
int uprobe_hpack_Encoder_WriteField(struct pt_regs *ctx) {
#ifndef NO_HEADER_PROPAGATION
    bpf_dbg_printk("=== uprobe/proc grpc hpack.(*Encoder).WriteField === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    void *field_ptr = GO_PARAM2(ctx); // read the incoming field name ptr (HeaderField)

    if (!field_ptr) {
        return 0;
    }

    // We need to read the first char of the HeaderField buffer, Name is first.
    u8 first_char = 0;
    bpf_probe_read(&first_char, sizeof(first_char), (void *)(field_ptr));

    // If the name starts with :, we skip processing. e.g. ':method'
    if (first_char == 0x3a) {
        bpf_dbg_printk("Skipping until we find non-protocol headers, field starts with `:`.");
        return 0;
    }

    grpc_client_func_invocation_t *invocation = bpf_map_lookup_elem(&ongoing_grpc_header_writes, &goroutine_addr);
    bpf_map_delete_elem(&ongoing_grpc_header_writes, &goroutine_addr);

    if (invocation) {
        void *e_ptr = GO_PARAM1(ctx);

        if (e_ptr) {
            void *w_ptr = 0;
            bpf_probe_read(&w_ptr, sizeof(w_ptr), (void *)(e_ptr + hpack_encoder_w_pos + sizeof(void *)));

            // No need to dereference one more time, w.buf is embedded.
            if (w_ptr) {
                void *buf_arr = 0;
                s64 len = 0;
                s64 cap = 0;

                bpf_probe_read(&buf_arr, sizeof(buf_arr), (void *)(w_ptr));
                bpf_probe_read(&len, sizeof(len), (void *)(w_ptr + 8));
                bpf_probe_read(&cap, sizeof(cap), (void *)(w_ptr + 16));

                bpf_dbg_printk("Found invocation w_ptr %llx, buf_arr %llx, len %d, cap %d", w_ptr, buf_arr, len, cap);

                if (len >= 0 && cap > 0 && cap > len) {
                    s64 available_bytes = (cap - len);
                
                    if (available_bytes > GRPC_ENCODED_HEADER_LEN) {
                        char key[TP_MAX_KEY_LENGTH] = "traceparent";
                        unsigned char tp_buf[TP_MAX_VAL_LENGTH];
                        u8 type_byte = 0;
                        u8 key_len = TP_MAX_KEY_LENGTH;
                        u8 val_len = TP_MAX_VAL_LENGTH;

                        make_tp_string(tp_buf, &invocation->tp);

                        bpf_dbg_printk("Will write %s", tp_buf);

                        // This mimics hpack encode appendNewName, assuming no Huffman encoding
                        // Write record type 0
                        bpf_probe_write_user(buf_arr + (len & 0x0ffff), &type_byte, sizeof(type_byte));
                        len++;
                        // Write the length of the key = 11
                        bpf_probe_write_user(buf_arr + (len & 0x0ffff), &key_len, sizeof(key_len));
                        len++;
                        // Write 'traceparent'
                        bpf_probe_write_user(buf_arr + (len & 0x0ffff), key, sizeof(key));
                        len += TP_MAX_KEY_LENGTH;
                        // Write the length of the traceparent field value = 55
                        bpf_probe_write_user(buf_arr + (len & 0x0ffff), &val_len, sizeof(val_len));
                        len++;
                        // Write the actual traceparent
                        bpf_probe_write_user(buf_arr + (len & 0x0ffff), tp_buf, sizeof(tp_buf));
                        len += TP_MAX_VAL_LENGTH;
                        // Update the buffer length to the new value
                        bpf_probe_write_user((void *)(w_ptr + 8), &len, sizeof(len));
                    }
                }
            } else {
                bpf_dbg_printk("Can't find w_ptr");
            }
        } else {
            bpf_dbg_printk("Can't find e_ptr");
        }

    }
#endif
    return 0;
}
