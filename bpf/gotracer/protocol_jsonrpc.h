#include <logger/bpf_dbg.h>
#include <common/tc_common.h>
#include <common/common.h>

static const char k_jsonrpc_key[] = "\"jsonrpc\"";
static const u32 k_jsonrpc_key_len = sizeof(k_jsonrpc_key) - 1;
static const char k_jsonrpc_val[] = "\"2.0\"";
static const u32 k_jsonrpc_val_len = sizeof(k_jsonrpc_val) - 1;
static const char k_application_json[] = "application/json";
static const u32 k_application_json_len = sizeof(k_application_json) - 1;
static const char k_method_key[] = "\"method\"";
static const u32 k_method_key_len = sizeof(k_method_key) - 1;

enum { JSONRPC_METHOD_BUF_SIZE = 16 };

// should match application/json, application/json-rpc, application/jsonrequest
// listed in https://www.jsonrpc.org/historical/json-rpc-over-http.html
static __always_inline u8 is_json_content_type(const char *c, u32 len) {
    if (len < k_application_json_len) {
        return 0;
    }
    // Check for "application/json" at the start
    if (c[0] == 'a' && c[1] == 'p' && c[2] == 'p' && c[3] == 'l' && c[4] == 'i' && c[5] == 'c' &&
        c[6] == 'a' && c[7] == 't' && c[8] == 'i' && c[9] == 'o' && c[10] == 'n' && c[11] == '/' &&
        c[12] == 'j' && c[13] == 's' && c[14] == 'o' && c[15] == 'n') {
        return 1;
    }
    return 0;
}

// ref: https://en.cppreference.com/w/c/string/byte/isspace
static __always_inline u8 bpf_isspace(char c) {
    return (c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v');
}

// Returns the offset of the next JSON value after skipping whitespace and colon.
// If not found, returns body_len.
static __always_inline u32 json_value_offset(const char *body, u32 body_len, u32 start_pos) {
    u32 pos = start_pos;
    while (pos < body_len && (bpf_isspace(body[pos]) || body[pos] == ':')) {
        pos++;
    }
    return pos;
}

// Returns the position of the first occurrence of a string in a JSON body.
// If not found, returns INVALID_POS.
static __always_inline u32 json_str_value(const char *body,
                                          u32 body_len,
                                          const char *str,
                                          u32 str_len) {
    return bpf_memstr((const char *)body, body_len, (const char *)str, str_len);
}

// Returns the end position (index of closing quote) of a JSON string value.
// If not found, returns body_len.
static __always_inline u32 json_str_value_end(const char *body, u32 body_len, u32 value_start) {
    // find_first_pos_of expects unsigned char*, so cast accordingly
    return value_start + find_first_pos_of((unsigned char *)(body + value_start),
                                           (unsigned char *)(body + body_len),
                                           '"');
}

/**
 * Copies a JSON string value from body[value_start..value_end) into dest_buf.
 * Ensures null-termination and does not exceed dest_buf_size.
 * Returns the number of bytes copied (excluding null terminator), or 0 on error.
 */
static __always_inline u32 copy_json_string_value(
    const char *body, u32 value_start, u32 value_end, char *dest_buf, u32 dest_buf_size) {
    u32 value_len = value_end - value_start;
    if (value_len <= 0)
        return 0;
    if (value_len >= dest_buf_size)
        value_len = dest_buf_size - 1; // leave space for null terminator

#pragma unroll
    for (u32 i = 0; i < dest_buf_size; i++) {
        if (i >= value_len)
            break;
        dest_buf[i] = body[value_start + i];
    }
    dest_buf[value_len] = '\0';
    return value_len;
}

// Looks for '"jsonrpc":"2.0"'
static __always_inline u32 is_jsonrpc2_body(const char *body, u32 body_len) {
    u32 key_pos = json_str_value(body, body_len, k_jsonrpc_key, k_jsonrpc_key_len);
    if (key_pos == INVALID_POS)
        return 0;

    bpf_dbg_printk("Found JSON-RPC 2.0 key");

    u32 val_search_start = json_value_offset(body, body_len, key_pos + k_jsonrpc_key_len);
    // The jsonrpc value should be a string
    if (val_search_start >= body_len || body[val_search_start] != '"')
        return 0;

    u32 val_pos = json_str_value(
        body + val_search_start, body_len - val_search_start, k_jsonrpc_val, k_jsonrpc_val_len);
    // The jsonrpc value should start immediately after the opening quote
    if (val_pos == INVALID_POS || val_pos != 0)
        return 0;

    bpf_dbg_printk("Found JSON-RPC 2.0 value");

    return 1; // JSON-RPC 2.0 detected
}

// Extracts the value of the "method" key from a JSON-RPC 2.0 body.
// Returns the length of the method value, or 0 if not found or error.
// method_buf must be at least method_buf_len bytes.
static __always_inline u32 extract_jsonrpc2_method(const char *body,
                                                   u32 body_len,
                                                   char *method_buf) {
    u32 key_pos = json_str_value(body, body_len, k_method_key, k_method_key_len);
    if (key_pos == INVALID_POS)
        return 0;

    bpf_dbg_printk("Found JSON-RPC method key");

    u32 val_search_start = json_value_offset(body, body_len, key_pos + k_method_key_len);
    // method value should be a string
    if (val_search_start >= body_len || body[val_search_start] != '"')
        return 0;

    bpf_dbg_printk("Found JSON-RPC method value opening quote");

    // Copy the method value from the body after the opening quote
    u32 value_start = val_search_start + 1;
    u32 value_end = json_str_value_end(body, body_len, value_start);

    return copy_json_string_value(
        body, value_start, value_end, method_buf, JSONRPC_METHOD_BUF_SIZE);
}