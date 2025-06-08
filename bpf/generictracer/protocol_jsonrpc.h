#include <logger/bpf_dbg.h>
#include <common/tc_common.h>

#define JSONRPC_KEY "\"jsonrpc\""
#define JSONRPC_KEY_LEN 9
#define JSONRPC_VAL "\"2.0\""
#define JSONRPC_VAL_LEN 5
#define APPLICATION_JSON "application/json"
#define APPLICATION_JSON_LEN 16
#define JSONRPC_METHOD_KEY "\"method\""
#define JSONRPC_METHOD_KEY_LEN 8
#define JSONRPC_METHOD_BUF_SIZE 16

static __always_inline int is_json_content_type(const char *content_type, int content_type_len) {
    return __builtin_memcmp(content_type, APPLICATION_JSON, APPLICATION_JSON_LEN) == 0;
}

// Looks for '"jsonrpc":"2.0"'
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

// Extracts the value of the "method" key from a JSON-RPC 2.0 body.
// Returns the length of the method value, or 0 if not found or error.
// method_buf must be at least method_buf_len bytes.
static __always_inline int
extract_jsonrpc2_method(const char *body, int body_len, char *method_buf) {
    int key_pos = bpf_memstr(body, body_len, JSONRPC_METHOD_KEY, JSONRPC_METHOD_KEY_LEN);
    if (key_pos < 0)
        return 0;

    bpf_dbg_printk("Found JSON-RPC method key");

    // Move past the key
    int val_search_start = key_pos + JSONRPC_METHOD_KEY_LEN;
    // Skip whitespace and colon
    while (val_search_start < body_len &&
           (body[val_search_start] == ' ' || body[val_search_start] == '\t' ||
            body[val_search_start] == '\n' || body[val_search_start] == ':')) {
        val_search_start++;
    }
    if (val_search_start >= body_len || body[val_search_start] != '"')
        return 0;

    bpf_dbg_printk("Found JSON-RPC method value opening quote");

    // Start of the value (after the opening quote)
    int value_start = val_search_start + 1;
    int value_end = value_start;
    // Find the closing quote, or stop at end of buffer
    while (value_end < body_len && body[value_end] != '"') {
        value_end++;
    }
    // If closing quote not found, value_end will be body_len

    int value_len = value_end - value_start;
    if (value_len <= 0)
        return 0;
    if (value_len >= JSONRPC_METHOD_BUF_SIZE)
        value_len = JSONRPC_METHOD_BUF_SIZE - 1; // leave space for null terminator

    // TODO: make it unrolled for performance
    // #pragma unroll
    for (int i = 0; i < JSONRPC_METHOD_BUF_SIZE; i++) {
        if (i >= value_len)
            break;
        method_buf[i] = body[value_start + i];
    }
    method_buf[value_len] = '\0';

    return value_len;
}