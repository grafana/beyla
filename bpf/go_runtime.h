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

#include "utils.h"
#include "bpf_dbg.h"
#include "go_common.h"

typedef struct new_func_invocation {
    u64 parent;
} new_func_invocation_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, void *); // key: pointer to the request goroutine
    __type(value, new_func_invocation_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} newproc1 SEC(".maps");

SEC("uprobe/runtime_newproc1")
int uprobe_proc_newproc1(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc newproc1 === ");
    void *creator_goroutine = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("creator_goroutine_addr %lx", creator_goroutine);

    new_func_invocation_t invocation = {.parent = (u64)GO_PARAM2(ctx)};

    // Save the registers on invocation to be able to fetch the arguments at return of newproc1
    if (bpf_map_update_elem(&newproc1, &creator_goroutine, &invocation, BPF_ANY)) {
        bpf_dbg_printk("can't update map element");
    }

    return 0;
}

SEC("uprobe/runtime_newproc1_return")
int uprobe_proc_newproc1_ret(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc newproc1 returns === ");
    void *creator_goroutine = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("creator_goroutine_addr %lx", creator_goroutine);

    // Lookup the newproc1 invocation metadata
    new_func_invocation_t *invocation = bpf_map_lookup_elem(&newproc1, &creator_goroutine);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read newproc1 invocation metadata");
        goto done;
    }

    // The parent goroutine is the second argument of newproc1
    void *parent_goroutine = (void *)invocation->parent;
    bpf_dbg_printk("parent goroutine_addr %lx", parent_goroutine);

    // The result of newproc1 is the new goroutine
    void *goroutine_addr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 pid = pid_from_pid_tgid(pid_tid);

    goroutine_key_t g_key = {.addr = (u64)goroutine_addr, .pid = pid};

    goroutine_metadata metadata = {
        .timestamp = bpf_ktime_get_ns(),
        .parent = {.addr = (u64)parent_goroutine, .pid = pid},
    };

    if (bpf_map_update_elem(&ongoing_goroutines, &g_key, &metadata, BPF_ANY)) {
        bpf_dbg_printk("can't update active goroutine");
    }

done:
    bpf_map_delete_elem(&newproc1, &creator_goroutine);

    return 0;
}

SEC("uprobe/runtime_goexit1")
int uprobe_proc_goexit1(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc goexit1 === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    u64 pid_tid = bpf_get_current_pid_tgid();
    u32 pid = pid_from_pid_tgid(pid_tid);

    goroutine_key_t g_key = {.addr = (u64)goroutine_addr, .pid = pid};

    bpf_map_delete_elem(&ongoing_goroutines, &g_key);
    // We also clean-up the go routine based trace map, it's an LRU
    // but at this point we are sure we don't need the data.
    bpf_map_delete_elem(&go_trace_map, &goroutine_addr);

    return 0;
}
