#ifndef BPF_DBG_H
#define BPF_DBG_H

#ifndef BPF_DEBUG
#define BPF_DEBUG 0
#endif

/* Helper macros to print out debug messages */
#define bpf_dbg_printk(fmt, args...)                                                               \
    if (BPF_DEBUG)                                                                                 \
    bpf_printk(fmt, ##args)

#endif
