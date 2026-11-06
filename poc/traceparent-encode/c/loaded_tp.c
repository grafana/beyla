#include "loaded_tp.h"

#include "sha256.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define SCHEME_MAGIC 0xB1

static uint32_t fnv32(const uint8_t *p, size_t n) {
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < n; i++) {
    h ^= p[i];
    h *= 16777619u;
  }
  return h;
}

static void kdf8(const uint8_t right[8], uint8_t pad[8]) {
  uint32_t a = fnv32(right, 8);
  uint8_t tmp[8];
  memcpy(tmp, right, 8);
  tmp[0] ^= 0x5a;
  uint32_t b = fnv32(tmp, 8);
  pad[0] = (uint8_t)(a >> 24);
  pad[1] = (uint8_t)(a >> 16);
  pad[2] = (uint8_t)(a >> 8);
  pad[3] = (uint8_t)a;
  pad[4] = (uint8_t)(b >> 24);
  pad[5] = (uint8_t)(b >> 16);
  pad[6] = (uint8_t)(b >> 8);
  pad[7] = (uint8_t)b;
}

static void lower_copy(const char *in, char *out, size_t cap) {
  size_t i = 0;
  if (!in) {
    out[0] = 0;
    return;
  }
  while (in[i] && i + 1 < cap) {
    out[i] = (char)tolower((unsigned char)in[i]);
    i++;
  }
  out[i] = 0;
}

void tp_identity_digest(const char *ns, const char *name, uint8_t out[32]) {
  char nsb[256], nmb[256];
  lower_copy(ns, nsb, sizeof nsb);
  lower_copy(name, nmb, sizeof nmb);
  uint8_t buf[16 + 1 + 256 + 1 + 256];
  const char *dom = "beyla.tpenc.v1";
  size_t o = 0;
  size_t dl = strlen(dom);
  memcpy(buf + o, dom, dl);
  o += dl;
  buf[o++] = 0;
  size_t nl = strlen(nsb);
  memcpy(buf + o, nsb, nl);
  o += nl;
  buf[o++] = 0;
  size_t ml = strlen(nmb);
  memcpy(buf + o, nmb, ml);
  o += ml;
  tp_sha256(buf, o, out);
}

int tp_encode(const char *origin_ns, const char *origin_name,
              const char *caller_ns, const char *caller_name,
              const uint8_t random_right[8], const uint8_t random_span[4],
              loaded_tp *out) {
  memset(out, 0, sizeof *out);
  uint8_t odig[32], cdig[32];
  tp_identity_digest(origin_ns, origin_name, odig);
  tp_identity_digest(caller_ns, caller_name, cdig);
  memcpy(out->origin_key, odig, TP_ORIGIN_KEY);
  memcpy(out->caller_key, cdig, TP_CALLER_KEY);

  uint8_t plain[8];
  plain[0] = SCHEME_MAGIC;
  memcpy(plain + 1, odig, 7);
  uint8_t pad[8];
  kdf8(random_right, pad);
  for (int i = 0; i < 8; i++) {
    out->trace_id[i] = (uint8_t)(plain[i] ^ pad[i]);
    out->trace_id[8 + i] = random_right[i];
  }
  for (int i = 0; i < 4; i++) {
    out->span_id[i] = (uint8_t)(cdig[i] ^ random_span[i]);
    out->span_id[4 + i] = random_span[i];
  }
  return 1;
}

int tp_parse_origin_key(const uint8_t trace_id[TP_TRACE_ID],
                        uint8_t key[TP_ORIGIN_KEY]) {
  uint8_t pad[8], plain[8];
  kdf8(trace_id + 8, pad);
  for (int i = 0; i < 8; i++) {
    plain[i] = (uint8_t)(trace_id[i] ^ pad[i]);
  }
  if (plain[0] != SCHEME_MAGIC) {
    return 0;
  }
  memcpy(key, plain + 1, TP_ORIGIN_KEY);
  return 1;
}

void tp_parse_caller_key(const uint8_t span_id[TP_SPAN_ID],
                         uint8_t key[TP_CALLER_KEY]) {
  for (int i = 0; i < 4; i++) {
    key[i] = (uint8_t)(span_id[i] ^ span_id[i + 4]);
  }
}

void tp_format(const loaded_tp *tp, char out[56]) {
  static const char *hex = "0123456789abcdef";
  out[0] = '0';
  out[1] = '0';
  out[2] = '-';
  int o = 3;
  for (int i = 0; i < 16; i++) {
    out[o++] = hex[tp->trace_id[i] >> 4];
    out[o++] = hex[tp->trace_id[i] & 0xf];
  }
  out[o++] = '-';
  for (int i = 0; i < 8; i++) {
    out[o++] = hex[tp->span_id[i] >> 4];
    out[o++] = hex[tp->span_id[i] & 0xf];
  }
  out[o++] = '-';
  out[o++] = '0';
  out[o++] = '1';
  out[o] = 0;
}
