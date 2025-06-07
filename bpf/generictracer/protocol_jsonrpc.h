#include <logger/bpf_dbg.h>
#include <common/tc_common.h>

#define JSONRPC_KEY "\"jsonrpc\""
#define JSONRPC_KEY_LEN 9
#define JSONRPC_VAL "\"2.0\""
#define JSONRPC_VAL_LEN 5
#define APPLICATION_JSON "application/json"
#define APPLICATION_JSON_LEN 16

static __always_inline int is_json_content_type(const char *content_type, int content_type_len) {
    return __builtin_memcmp(content_type, APPLICATION_JSON, APPLICATION_JSON_LEN) == 0;
}

// Looks for '"jsonrpc":"2.0"' and '"method":"'
static __always_inline int is_jsonrpc2_body(const char *body, int body_len) {
    int key_pos = bpf_memstr(body, body_len, JSONRPC_KEY, JSONRPC_KEY_LEN);
    if (key_pos < 0)
        return 0;

    bpf_dbg_printk("Found JSON-RPC 2.0 key");

    // Look for value after the key (skip whitespace and colon)
    int val_search_start = key_pos + JSONRPC_KEY_LEN;
    // Skip whitespace and colon
    while (val_search_start < body_len &&
           (body[val_search_start] == ' ' || body[val_search_start] == '\t' ||
            body[val_search_start] == '\n' || body[val_search_start] == ':')) {
        val_search_start++;
    }
    if (val_search_start >= body_len)
        return 0;

    int val_pos = bpf_memstr(
        body + val_search_start, body_len - val_search_start, JSONRPC_VAL, JSONRPC_VAL_LEN);
    if (val_pos < 0)
        return 0;

    bpf_dbg_printk("Found JSON-RPC 2.0 value");

    return 1; // JSON-RPC 2.0 detected
}