#include "loaded_tp.h"

#include <stdio.h>
#include <string.h>

static const uint8_t k_right[8] = {0x01, 0x23, 0x45, 0x67,
                                   0x89, 0xab, 0xcd, 0xef};
static const uint8_t k_span[4] = {0xde, 0xad, 0xbe, 0xef};

static void print_hex(const char *label, const uint8_t *p, int n) {
  printf("%s", label);
  for (int i = 0; i < n; i++) {
    printf("%02x", p[i]);
  }
  printf("\n");
}

static int selftest(void) {
  const char *ns[] = {"", "prod", "production", "customer-prod"};
  const char *nm[] = {"nginx", "api",
                      "very-long-deployment-name-that-will-not-fit",
                      "order-processing-worker"};
  int failed = 0;
  for (int i = 0; i < 4; i++) {
    loaded_tp tp;
    tp_encode(ns[i], nm[i], ns[i], nm[i], k_right, k_span, &tp);
    uint8_t ok[7], ck[4];
    if (!tp_parse_origin_key(tp.trace_id, ok)) {
      printf("FAIL origin magic %s/%s\n", ns[i], nm[i]);
      failed++;
      continue;
    }
    if (memcmp(ok, tp.origin_key, 7) != 0) {
      printf("FAIL origin key %s/%s\n", ns[i], nm[i]);
      failed++;
    }
    tp_parse_caller_key(tp.span_id, ck);
    if (memcmp(ck, tp.caller_key, 4) != 0) {
      printf("FAIL caller key %s/%s\n", ns[i], nm[i]);
      failed++;
    }
    char hdr[56];
    tp_format(&tp, hdr);
    if (strlen(hdr) != 55) {
      printf("FAIL header len\n");
      failed++;
    }
    printf("OK  %s  origin=", hdr);
    for (int j = 0; j < 7; j++) {
      printf("%02x", tp.origin_key[j]);
    }
    printf(" caller=");
    for (int j = 0; j < 4; j++) {
      printf("%02x", tp.caller_key[j]);
    }
    printf("\n");
  }
  loaded_tp demo;
  tp_encode("prod", "api", "prod", "api", k_right, k_span, &demo);
  print_hex("vector.trace_id=", demo.trace_id, 16);
  print_hex("vector.span_id=", demo.span_id, 8);
  print_hex("vector.origin_key=", demo.origin_key, 7);
  print_hex("vector.caller_key=", demo.caller_key, 4);
  return failed;
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "selftest") == 0) {
    return selftest() ? 1 : 0;
  }
  const char *ns = "";
  const char *name = "nginx";
  if (argc >= 3) {
    ns = argv[1];
    name = argv[2];
  } else if (argc == 2) {
    name = argv[1];
  }
  loaded_tp tp;
  tp_encode(ns, name, ns, name, k_right, k_span, &tp);
  char hdr[56];
  tp_format(&tp, hdr);
  printf("%s\n", hdr);
  print_hex("origin=", tp.origin_key, 7);
  print_hex("caller=", tp.caller_key, 4);
  return 0;
}
