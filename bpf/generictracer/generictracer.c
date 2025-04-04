//go:build beyla_bpf_ignore
#include "k_tracer.c"
#include "http_ssl.c"
#include "nodejs.c"

char __license[] SEC("license") = "Dual MIT/GPL";
