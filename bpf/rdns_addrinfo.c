#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "bpf_tracing.h"
#include "bpf_dbg.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define HOSTNAME_MAX_LEN 64

// structure copied/adapted from "netdb.h"
struct addrinfo {
    int ai_flags;     /* Input flags.  */
    int ai_family;    /* Protocol family for socket.  */
    int ai_socktype;  /* Socket type.  */
    int ai_protocol;  /* Protocol for socket.  */
    u32 ai_addrlen;   /* Length of socket address. Originally socklen_t (u32) */
    u64 ai_addr;      /* Socket address for socket. Originally struct sockaddr* (u64) */
    u64 ai_canonname; /* Canonical name for service location.  Originally char* (u64) */
    u64 ai_next;      /* Pointer to next in list. Originally struct addrinfo* (u64)  */
};

typedef struct addr_request {
    u8 name[HOSTNAME_MAX_LEN];
    u64 addrinfo_ptr_ptr;
} __attribute__((packed)) addr_request_t;

typedef struct dns_entry {
    u8 name[HOSTNAME_MAX_LEN];
    u8 ip[16];
} __attribute__((packed)) dns_entry_t;

// Force emitting struct dns_entry_t into the ELF for automatic creation of Golang struct
const dns_entry_t *unused_dns_entry_t __attribute__((unused));
const addr_request_t *unused_addr_request_t __attribute__((unused));

// The ringbuffer is used to forward messages directly to the user space (Go program)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} resolved SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, addr_request_t);
    __uint(max_entries, 1024);
} ongoings SEC(".maps");

SEC("uprobe/libc.so.6:getaddrinfo")
int BPF_UPROBE(uprobe_getaddrinfo,
               const char *name,
               const char *service,
               const void *hints, //const struct addrinfo *hints,
               void **pai) {      //struct addrinfo **pai

    u64 id = bpf_get_current_pid_tgid();

    addr_request_t entry;
    bpf_probe_read_str(entry.name, HOSTNAME_MAX_LEN, name);
    entry.addrinfo_ptr_ptr = (u64)pai;

    bpf_map_update_elem(&ongoings, &id, &entry, BPF_ANY);

    return 0;
}

SEC("uretprobe/libc.so.6:getaddrinfo")
int BPF_KRETPROBE(uretprobe_getaddrinfo, int ret) { //struct addrinfo **pai
    u64 id = bpf_get_current_pid_tgid();
    addr_request_t *ongoing = bpf_map_lookup_elem(&ongoings, &id);
    if (ongoing == NULL) {
        bpf_printk("Failed to find ongoing call\n");
        return 0;
    }
    // addr_ptr = *(ongoing->addrinfo_ptr_ptr)
    u64 addr_ptr;
    if (bpf_probe_read(&addr_ptr, sizeof(addr_ptr), (void *)(ongoing->addrinfo_ptr_ptr)) < 0) {
        bpf_printk(
            "Failed to read addrinfo_ptr_ptr %s %ld\n", ongoing->name, ongoing->addrinfo_ptr_ptr);
        return 0;
    }
    // addr = addr_ptr->ai_addr
    struct addrinfo ai;
    if (bpf_probe_read(&ai, sizeof(ai), (void *)addr_ptr) < 0) {
        bpf_printk("Failed to read addr_ptr\n");
        return 0;
    }
    if (ai.ai_addr == (u64)NULL) {
        bpf_printk("ai_addr is NULL %ld\n", ai.ai_addrlen);
        return 0;
    }

    // first addrinfo will lead us to 0.0.0.0 addresses. Move to ai_next
    // TODO: move to next addresses like
    // if (bpf_probe_read(&ai, sizeof(ai), (void *)ai.ai_next) < 0) {
    //     bpf_printk("Failed to read addr->ai_next\n");
    //     return 0;
    // }
    // Assuming ipv4: TODO: check ai_family == AF_INET or ipv6
    struct sockaddr_in sa;
    if (bpf_probe_read(&sa, sizeof(sa), (void *)ai.ai_addr) < 0) {
        bpf_printk("Failed to read ai_addr\n");
        return 0;
    }
    dns_entry_t *info = bpf_ringbuf_reserve(&resolved, sizeof(dns_entry_t), 0);
    if (!info) {
        bpf_printk("Failed to reserve ringbuf\n");
        return 0;
    }

    bpf_printk("IP: %08x", sa.sin_addr);
    if (bpf_probe_read(info->ip, sizeof(sa.sin_addr.s_addr), (void *)&(sa.sin_addr.s_addr)) < 0) {
        bpf_printk("Failed to read ip\n");
    }
    bpf_probe_read_str(info->name, HOSTNAME_MAX_LEN, ongoing->name);
    bpf_ringbuf_submit(info, 0);
    return 0;
}
