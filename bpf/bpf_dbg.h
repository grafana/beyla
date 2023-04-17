#ifndef BPF_DBG_H
#define BPF_DBG_H

#ifdef BPF_DEBUG
#define bpf_dbg_printk(fmt, args...) bpf_printk(fmt, ##args)
#else
#define bpf_dbg_printk(fmt, args...)
#endif

#endif

