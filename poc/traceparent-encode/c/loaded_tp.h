#ifndef LOADED_TP_H
#define LOADED_TP_H

#include <stddef.h>
#include <stdint.h>

enum { TP_TRACE_ID = 16, TP_SPAN_ID = 8, TP_ORIGIN_KEY = 7, TP_CALLER_KEY = 4 };

typedef struct {
  uint8_t trace_id[TP_TRACE_ID];
  uint8_t span_id[TP_SPAN_ID];
  uint8_t origin_key[TP_ORIGIN_KEY];
  uint8_t caller_key[TP_CALLER_KEY];
} loaded_tp;

void tp_identity_digest(const char *ns, const char *name, uint8_t out[32]);
int tp_encode(const char *origin_ns, const char *origin_name,
              const char *caller_ns, const char *caller_name,
              const uint8_t random_right[8], const uint8_t random_span[4],
              loaded_tp *out);
int tp_parse_origin_key(const uint8_t trace_id[TP_TRACE_ID],
                        uint8_t key[TP_ORIGIN_KEY]);
void tp_parse_caller_key(const uint8_t span_id[TP_SPAN_ID],
                         uint8_t key[TP_CALLER_KEY]);
void tp_format(const loaded_tp *tp, char out[56]);

#endif
