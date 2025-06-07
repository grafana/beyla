#include <logger/bpf_dbg.h>
#include <common/tc_common.h>

// Looks for '"jsonrpc":"2.0"' and '"method":"'
static __always_inline int is_jsonrpc2_body(const char *body, int body_len) {
    // Look for "jsonrpc":"2.0"
    const char *jsonrpc_key = "\"jsonrpc\"";
    const char *jsonrpc_val = "\"2.0\"";
    int key_pos = bpf_memstr(body, body_len, jsonrpc_key, sizeof(jsonrpc_key));
    if (key_pos < 0)
        return 0;

    bpf_dbg_printk("Found JSON-RPC 2.0 key");

    // Find ':' after the key
    int colon_pos = key_pos + 10;
    while (colon_pos < body_len &&
           (body[colon_pos] == ' ' || body[colon_pos] == '\t' || body[colon_pos] == '\n'))
        colon_pos++;
    if (colon_pos >= body_len || body[colon_pos] != ':')
        return 0;
    colon_pos++;

    // Skip whitespace
    while (colon_pos < body_len &&
           (body[colon_pos] == ' ' || body[colon_pos] == '\t' || body[colon_pos] == '\n'))
        colon_pos++;
    if (colon_pos >= body_len)
        return 0;

    // Check for value
    if (bpf_memstr(body + colon_pos, body_len - colon_pos, jsonrpc_val, sizeof(jsonrpc_val)) != 0)
        return 0;

    bpf_dbg_printk("Found JSON-RPC 2.0 value");

    // Look for "method" key
    const char *method_key = "\"method\"";
    int method_pos = bpf_memstr(body, body_len, method_key, sizeof(method_key));
    if (method_pos < 0)
        return 0;

    bpf_dbg_printk("Found JSON-RPC 2.0 method");

    // Optionally: extract method value here

    return 1; // JSON-RPC 2.0 detected
}