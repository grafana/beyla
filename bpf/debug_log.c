//go:build beyla_bpf_ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_dbg.h"

#ifdef BPF_DEBUG
const log_info_t *unused_100 __attribute__((unused));
#endif
