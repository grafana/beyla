// SPDX-License-Identifier: Apache-2.0
// important to be first:
#include <bpfcore/vmlinux.h>

// others
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>

#include <pid/types/pid_data.h>

#define S_IFMT 0xF000   // File type mask.
#define S_IFSOCK 0xC000 // Socket file type.

#define SURVEY_SOCK_ANY (1 << 0)     // any socket use
#define SURVEY_SOCK_PRIV (1 << 1)    // listens on a privileged port (< 1024)
#define SURVEY_SOCK_NONPRIV (1 << 2) // listens on an unprivileged port

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct survey_process {
  u64 start_time;
  pid_data_t id;
};

// This is evidence of having used a socket, not a count of currently open
// sockets. We never evict live processes, closing a short-lived connection must
// not revoke admission. The value is a SURVEY_SOCK_* bitmask.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, struct survey_process);
  __type(value, u8);
} survey_socket_pids SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 16);
} survey_socket_events SEC(".maps");

static __always_inline struct survey_process
process_key(struct task_struct *task) {
  struct task_struct *leader = BPF_CORE_READ(task, group_leader);
  struct survey_process key = {};
  struct pid *pid = BPF_CORE_READ(leader, thread_pid);
  unsigned int level = BPF_CORE_READ(pid, level);
  struct upid number = {};

  // OBI's namespace PID identity. Read the active namespace through thread_pid
  // so this also works at sched_process_exit, after task->nsproxy is cleared.
  bpf_core_read(&number, sizeof(number), &pid->numbers[level]);
  key.id.pid = number.nr;
  key.id.ns = BPF_CORE_READ(number.ns, ns.inum);

  key.start_time = BPF_CORE_READ(leader, start_boottime) / 10000000ULL;
  return key;
}

static __always_inline void remember_socket(struct task_struct *task, u8 flags,
                                            bool notify) {
  if (!task || BPF_CORE_READ(task, signal, live.counter) == 0) {
    return;
  }

  struct survey_process key = process_key(task);
  if (!key.id.pid) {
    return;
  }

  u8 *existing = bpf_map_lookup_elem(&survey_socket_pids, &key);
  if (existing) {
    u8 merged = *existing | flags;
    if (merged != *existing) {
      bpf_map_update_elem(&survey_socket_pids, &key, &merged, BPF_EXIST);
      if (notify) {
        bpf_ringbuf_output(&survey_socket_events, &key, sizeof(key), 0);
      }
    }
    return;
  }

  bpf_map_update_elem(&survey_socket_pids, &key, &flags, BPF_NOEXIST);

  // An iterator can race the last thread's exit. Don't leave its evidence
  // behind.
  if (BPF_CORE_READ(task, signal, live.counter) == 0) {
    bpf_map_delete_elem(&survey_socket_pids, &key);
    return;
  }

  if (notify) {
    // The map is authoritative. A full ring buffer must not lose the evidence.
    bpf_ringbuf_output(&survey_socket_events, &key, sizeof(key), 0);
  }
}

// Classifies a bound port as privileged or not. Port 0 means unbound.
static __always_inline u8 port_flags(u16 port) {
  if (port == 0) {
    return 0;
  }

  return port < 1024 ? SURVEY_SOCK_PRIV : SURVEY_SOCK_NONPRIV;
}

// These hooks receive validated sockets and also cover nonblocking/failed
// attempts, Unix sockets, and io_uring operations. There is deliberately no OBI
// PID filter.
SEC("kprobe/security_socket_connect")
int survey_watch_connect(void *ctx) {
  remember_socket((struct task_struct *)bpf_get_current_task(), SURVEY_SOCK_ANY,
                  true);
  return 0;
}

SEC("kprobe/security_socket_listen")
int survey_watch_listen(struct socket *sock, int backlog) {
  struct sock *sk = BPF_CORE_READ(sock, sk);
  u16 port = BPF_CORE_READ(sk, __sk_common.skc_num);

  remember_socket((struct task_struct *)bpf_get_current_task(),
                  SURVEY_SOCK_ANY | port_flags(port), true);
  return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int survey_watch_exit(void *ctx) {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  // sched_process_exit runs after signal->live is decremented. A worker thread
  // exiting must not erase evidence belonging to the rest of its thread group.
  if (BPF_CORE_READ(task, signal, live.counter) == 0) {
    struct survey_process key = process_key(task);
    bpf_map_delete_elem(&survey_socket_pids, &key);
  }

  return 0;
}

SEC("iter/task_file")
int survey_seed_sockets(struct bpf_iter__task_file *ctx) {
  struct file *file = ctx->file;

  if (file && (BPF_CORE_READ(file, f_inode, i_mode) & S_IFMT) == S_IFSOCK) {
    // Task/file iteration preserves ownership across network namespaces and
    // includes inherited listeners, accepted connections, and keepalives.
    u8 flags = SURVEY_SOCK_ANY;
    struct socket *sock = (struct socket *)BPF_CORE_READ(file, private_data);
    if (sock) {
      struct sock *sk = BPF_CORE_READ(sock, sk);
      if (sk) {
        u16 port = BPF_CORE_READ(sk, __sk_common.skc_num);
        u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);
        // UDP sockets have no listen state. Their bound port is recorded as
        // evidence of serving.
        if (state == TCP_LISTEN || BPF_CORE_READ(sk, sk_type) == SOCK_DGRAM) {
          flags |= port_flags(port);
        }
      }
    }

    remember_socket(ctx->task, flags, false);
  }

  return 0;
}
