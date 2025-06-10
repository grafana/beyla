//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <logger/bpf_dbg.h>

#ifdef BPF_DEBUG
const log_info_t *unused_100 __attribute__((unused));
#endif
