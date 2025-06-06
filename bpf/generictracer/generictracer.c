//go:build obi_bpf_ignore
#include "k_tracer.c"
#include "libssl.c"
#include "nginx.c"

char __license[] SEC("license") = "Dual MIT/GPL";
