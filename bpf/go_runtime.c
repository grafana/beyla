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

SEC("uprobe/runtime_newproc1")
int uprobe_proc_newproc1(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc newproc1 === ");
    void *creator_goroutine = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("creator_goroutine_addr %lx", creator_goroutine);

    func_invocation invocation = {
        .regs = *ctx,
    };

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
    func_invocation *invocation =
        bpf_map_lookup_elem(&newproc1, &creator_goroutine);
    bpf_map_delete_elem(&newproc1, &creator_goroutine);
    if (invocation == NULL) {
        bpf_dbg_printk("can't read newproc1 invocation metadata");
        return 0;
    }

    // The parent goroutine is the second argument of newproc1
    void *parent_goroutine = (void *)GO_PARAM2(&invocation->regs);
    bpf_dbg_printk("parent goroutine_addr %lx", parent_goroutine);

    // The result of newproc1 is the new goroutine
    void *goroutine_addr = (void *)GO_PARAM1(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    goroutine_metadata metadata = {
        .timestamp = bpf_ktime_get_ns(),
        .parent = (u64)parent_goroutine,
    };

    if (bpf_map_update_elem(&ongoing_goroutines, &goroutine_addr, &metadata, BPF_ANY)) {
        bpf_dbg_printk("can't update active goroutine");
    }

    return 0;
}

SEC("uprobe/runtime_goexit1")
int uprobe_proc_goexit1(struct pt_regs *ctx) {
    bpf_dbg_printk("=== uprobe/proc goexit1 === ");

    void *goroutine_addr = GOROUTINE_PTR(ctx);
    bpf_dbg_printk("goroutine_addr %lx", goroutine_addr);

    bpf_map_delete_elem(&ongoing_goroutines, &goroutine_addr);
    // We also clean-up ongoing_server_requests so that we can handle hijacked requests, where the ServeHTTP
    // finishes, but we never call WriteHeader to clean-up the ongoing requests
    bpf_map_delete_elem(&ongoing_server_requests, &goroutine_addr);

    return 0;
}
