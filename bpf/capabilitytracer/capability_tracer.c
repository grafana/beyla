#include <bpfcore/utils.h>
#include <gotracer/go_common.h>
// #include <linux/sched.h>

typedef struct capability_info {
    int cap;
    u64 pid;
    __u8 comm[16];
    // char comm[TASK_COMM_LEN];
} capability_info_t;

const capability_info_t *unused_2 __attribute__((unused));

// Temporary tracking of capabilities
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} capability_events SEC(".maps");

SEC("kprobe/capable")
int BPF_KPROBE(beyla_kprobe_capable, int cap) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    capability_info_t *trace = 
        bpf_ringbuf_reserve(&capability_events, sizeof(capability_info_t), 0);
    if (trace) {
        //TODO: Log the system time. Can we use bpf_ktime_get_tai_ns?
        // https://docs.ebpf.io/linux/helper-function/bpf_ktime_get_tai_ns/
        // bpf_map_update_elem(&capability_events, &id, &cap, BPF_ANY);

        trace->cap = cap;
        trace->pid = pid;

        bpf_get_current_comm(&trace->comm, sizeof(trace->comm));


        bpf_dbg_printk("=== capability with id=%d used by process=%s with pid=%u ===", trace->cap, trace->comm, trace->pid);
        bpf_ringbuf_submit(trace, 0);
    }

    return 0;
}
