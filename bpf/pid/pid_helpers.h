#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <pid/types/pid_info.h>
#include <pid/types/pid_key.h>

// Good resource on this: https://mozillazg.com/2022/05/ebpf-libbpfgo-get-process-info-en.html
// Using bpf_get_ns_current_pid_tgid is too restrictive for us
static __always_inline void
ns_pid_ppid(struct task_struct *task, int *pid, int *ppid, u32 *pid_ns_id) {
    struct upid upid;

    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);

    *pid = upid.nr;
    unsigned int p_level = BPF_CORE_READ(task, real_parent, nsproxy, pid_ns_for_children, level);

    struct pid *ns_ppid = (struct pid *)BPF_CORE_READ(task, real_parent, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_ppid->numbers[p_level]);
    *ppid = upid.nr;

    struct ns_common ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns);
    *pid_ns_id = ns.inum;
}

// sets the pid_info value from the current task
static __always_inline void task_pid(pid_info *pid) {
    struct upid upid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // set host-side PID
    pid->host_pid = (u32)BPF_CORE_READ(task, tgid);

    // set user-side PID
    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);
    pid->user_pid = (u32)upid.nr;

    // set PIDs namespace
    struct ns_common ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns);
    pid->ns = (u32)ns.inum;
}

static __always_inline u32 get_task_tid() {
    struct upid upid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // https://github.com/torvalds/linux/blob/556e2d17cae620d549c5474b1ece053430cd50bc/kernel/pid.c#L324 (type is )
    // set user-side PID
    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);

    return (u32)upid.nr;
}

static __always_inline void task_tid(pid_key_t *tid) {
    struct upid upid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // https://github.com/torvalds/linux/blob/556e2d17cae620d549c5474b1ece053430cd50bc/kernel/pid.c#L324 (type is )
    // set user-side PID
    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);
    tid->tid = (u32)upid.nr;
    ns_pid = (struct pid *)BPF_CORE_READ(task, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);
    tid->pid = (u32)upid.nr;

    // set PIDs namespace
    struct ns_common ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns);
    tid->ns = (u32)ns.inum;
}

static __always_inline u32 pid_from_pid_tgid(u64 id) {
    return (u32)(id >> 32);
}

static __always_inline u64 to_pid_tgid(u32 pid, u32 tid) {
    return (u64)((u64)pid << 32) | tid;
}
