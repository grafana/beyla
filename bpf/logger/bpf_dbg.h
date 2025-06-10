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

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>

#include <common/pin_internal.h>

#ifdef BPF_DEBUG

typedef struct log_info {
    u64 pid;
    unsigned char log[80];
    unsigned char comm[20];
    u8 _pad[4];
} log_info_t;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
    __uint(pinning, BEYLA_PIN_INTERNAL);
} debug_events SEC(".maps");

enum bpf_func_id___x { BPF_FUNC_snprintf___x = 42 /* avoid zero */ };

// When DEBUG_TC is enabled through build options it means we are compiling the Traffic Control TC
// BPF program. In TC we can't use the current comm or current_pid_tgid helpers. We could use
// get_current_task and extract the PID, but it's usually not the right PID anyway.
#ifdef BPF_DEBUG_TC
#define bpf_dbg_helper(fmt, args...)                                                               \
    {                                                                                              \
        log_info_t *__trace__ = bpf_ringbuf_reserve(&debug_events, sizeof(log_info_t), 0);         \
        if (__trace__) {                                                                           \
            if (bpf_core_enum_value_exists(enum bpf_func_id___x, BPF_FUNC_snprintf___x)) {         \
                BPF_SNPRINTF((char *)__trace__->log, sizeof(__trace__->log), fmt, ##args);         \
            } else {                                                                               \
                __builtin_memcpy(__trace__->log, fmt, sizeof(__trace__->log));                     \
            }                                                                                      \
            bpf_ringbuf_submit(__trace__, 0);                                                      \
        }                                                                                          \
    }
#else // BPF_DEBUG_TC
#define bpf_dbg_helper(fmt, args...)                                                               \
    {                                                                                              \
        log_info_t *__trace__ = bpf_ringbuf_reserve(&debug_events, sizeof(log_info_t), 0);         \
        if (__trace__) {                                                                           \
            if (bpf_core_enum_value_exists(enum bpf_func_id___x, BPF_FUNC_snprintf___x)) {         \
                BPF_SNPRINTF((char *)__trace__->log, sizeof(__trace__->log), fmt, ##args);         \
            } else {                                                                               \
                __builtin_memcpy(__trace__->log, fmt, sizeof(__trace__->log));                     \
            }                                                                                      \
            u64 id = bpf_get_current_pid_tgid();                                                   \
            bpf_get_current_comm(&__trace__->comm, sizeof(__trace__->comm));                       \
            __trace__->pid = id >> 32;                                                             \
            bpf_ringbuf_submit(__trace__, 0);                                                      \
        }                                                                                          \
    }
#endif // BPF_DEBUG_TC

#define bpf_dbg_printk(fmt, args...)                                                               \
    {                                                                                              \
        bpf_printk(fmt, ##args);                                                                   \
        bpf_dbg_helper(fmt, ##args);                                                               \
    }
#define bpf_d_printk(fmt, args...)                                                                 \
    {                                                                                              \
        bpf_printk(fmt, ##args);                                                                   \
    }
#else
#define bpf_dbg_printk(fmt, args...)
#define bpf_d_printk(fmt, args...)
#endif
