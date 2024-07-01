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
#ifndef BPF_DBG_H
#define BPF_DBG_H

#ifdef BPF_DEBUG

typedef struct log_info {
    char log[80];
    char comm[20];
    u64 pid;
} log_info_t;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
    __uint(pinning, LIBBPF_PIN_BY_NAME);    
} debug_events SEC(".maps");

enum bpf_func_id___x { BPF_FUNC_snprintf___x = 42 /* avoid zero */ };

#define bpf_dbg_helper(fmt, args...) { \
    if(bpf_core_enum_value_exists(enum bpf_func_id___x, BPF_FUNC_snprintf___x)) { \
        log_info_t *__trace__ = bpf_ringbuf_reserve(&debug_events, sizeof(log_info_t), 0); \
        if (__trace__) { \
            BPF_SNPRINTF(__trace__->log, sizeof(__trace__->log), fmt, ##args); \
            u64 id = bpf_get_current_pid_tgid(); \
            bpf_get_current_comm(&__trace__->comm, sizeof(__trace__->comm)); \
            __trace__->pid = id >> 32; \
            bpf_ringbuf_submit(__trace__, 0); \
        } \
    } \
}

#define bpf_dbg_printk(fmt, args...) { \
    bpf_printk(fmt, ##args); \
    bpf_dbg_helper(fmt, ##args); \
}
#else
#define bpf_dbg_printk(fmt, args...)
#endif

#endif

