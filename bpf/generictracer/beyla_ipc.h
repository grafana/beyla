#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>

#include <logger/bpf_dbg.h>

#include <maps/nodejs_fd_map.h>

// at the moment, this is only used by the nodejs agent (fdextractor) to
// communicate the file descriptors of the incoming and outgoing calls - this
// could be extended in the future (and potentially become a tail call target)
static __always_inline int handle_beyla_ipc(const void *buf, u8 buf_size) {
    struct hdr_t {
        u32 marker;
        u32 fd1; // fd of the server call
        u32 fd2; // fd of the client call
    };

    const struct hdr_t *hdr = (const struct hdr_t *)buf;

    const u32 marker = bpf_ntohl(hdr->marker);
    const u64 pid_tgid = bpf_get_current_pid_tgid();
    const s32 fd1 = bpf_ntohl(hdr->fd1);
    const s32 fd2 = bpf_ntohl(hdr->fd2);

    enum { k_beyla_ipc_magic = 0xbe14be14 };

    if (marker != k_beyla_ipc_magic) {
        return 0;
    }

    const u64 key = (pid_tgid << 32) | fd2;
    bpf_map_update_elem(&nodejs_fd_map, &key, &fd1, BPF_ANY);

    bpf_dbg_printk("[beyla_ipc] pid=%u, fd1=%d, fd2=%d", pid_tgid, fd1, fd2);

    return 1;
}
