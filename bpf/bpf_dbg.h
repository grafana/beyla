#ifndef BPF_DBG_H
#define BPF_DBG_H

#ifndef DBG_LEVEL
    #error "You must define DBG_LEVEL before including this file"
#endif

#define PRINTK_LEVEL_ERROR 0
#define PRINTK_LEVEL_WARN  1
#define PRINTK_LEVEL_INFO  2
#define PRINTK_LEVEL_DEBUG 3

/* Helper macros to print out debug messages */
#define bpf_dbg_printk(fmt, args...)                                                               \
    if (DBG_LEVEL >= PRINTK_LEVEL_DEBUG)                                                           \
    bpf_printk(fmt, ##args)
#define bpf_warn_printk(fmt, args...)                                                              \
    if (DBG_LEVEL >= PRINTK_LEVEL_WARN)                                                            \
    bpf_printk(fmt, ##args)
#define bpf_error_printk(fmt, args...)                                                             \
    if (DBG_LEVEL >= PRINTK_LEVEL_ERROR)                                                           \
    bpf_printk(fmt, ##args)
#define bpf_info_printk(fmt, args...)                                                              \
    if (DBG_LEVEL >= PRINTK_LEVEL_INFO)                                                            \
    bpf_printk(fmt, ##args)

#endif
