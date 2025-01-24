/**
 * Tests the following function, adapted from it:
 * static __always_inline write_traceparent(struct __sk_buff *skb,
                                         protocol_info_t *tcp,
                                         egress_key_t *e_key,
                                         tc_http_ctx_t *ctx,
                                         unsigned char *tp_buf) {
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct sk_buf {
  int tot_len;
  char data[256];
} sk_buf_t;

typedef struct tc_http_ctx {
  unsigned int offset;  // where inside the original packet we saw '\n`
  unsigned int seen;    // how many bytes we've seen before the offset
  unsigned int written; // how many of the Traceparent field we've written
} tc_http_ctx_t;

const int hdr_len = 12;

const unsigned char TP[] =
    "Traceparent: 12-34567891234567891234567891234567-8912345678912345-67\r\n";
const unsigned int EXTEND_SIZE = sizeof(TP) - 1;

void bpf_clamp_umax(unsigned int *off, unsigned int val) {
  if (*off > val) {
    *off = val;
  }
}

int write_traceparent(sk_buf_t *skb, tc_http_ctx_t *ctx,
                      unsigned char *tp_buf) {
  unsigned int tot_len = skb->tot_len;
  unsigned int packet_size = tot_len - hdr_len;
  printf("Writing traceparent packet_size %d, offset %d, tot_len %d\n",
         packet_size, ctx->offset, tot_len);
  printf("seen %d, written %d\n", ctx->seen, ctx->written);

  if (packet_size > 0) {
    unsigned int len = 0;
    unsigned int off = hdr_len;
    // picked a value large enough to support TCP headers
    bpf_clamp_umax(&off, 128);
    char *start = skb->data + off;

    // We haven't seen enough bytes coming through from the start
    // until we did the split (at ctx->offset is where we injected)
    // the empty space.
    if (ctx->seen < ctx->offset) {
      // Diff = How much more before we cross offset
      unsigned int diff = ctx->offset - ctx->seen;
      // We received less or equal bytes to what we want to
      // reach ctx->offset, i.e the split point.
      if (diff > packet_size) {
        ctx->seen += packet_size;
        return 0;
      } else {
        start += diff;
        ctx->seen = ctx->offset;
        // We went over the split point, calculate how much can we
        // write, but cap it to the max size = 70 bytes.
        len = packet_size - diff;
        bpf_clamp_umax(&len, EXTEND_SIZE);
      }
    } else {
      // Fast path. We are exactly at the offset, we've written
      // nothing of the 'Traceparent: ...' text yet and the packet
      // is exactly 70 bytes.
      if (ctx->written == 0 && packet_size == EXTEND_SIZE) {
        if ((start + EXTEND_SIZE) <= &skb->data[255]) {
          memcpy(start, tp_buf, EXTEND_SIZE);
          printf("Set the string fast_path!\n");

          return 0;
        }
      }

      // Nope, we've written some bytes in another packet and we
      // are not done writing yet.
      if (ctx->written < EXTEND_SIZE) {
        len = EXTEND_SIZE - ctx->written;
        bpf_clamp_umax(&len, EXTEND_SIZE);

        if (len > packet_size) {
          len = packet_size;
        }
      } else {
        // We've written everything already, just clean up
        return 0;
      }
    }

    if (len > 0) {
      unsigned int tp_off = ctx->written;
      // Keeps verifier happy
      bpf_clamp_umax(&tp_off, EXTEND_SIZE);
      bpf_clamp_umax(&len, EXTEND_SIZE);

      if ((start + len) <= &skb->data[255]) {
        memcpy((char *)start, (char *)tp_buf + tp_off, len);
        printf("Set the string off = %d, len = %d!\n", tp_off, len);
      }

      ctx->written += len;
      // If we've written the full string this time around
      // cleanup the metadata.
      if (ctx->written >= EXTEND_SIZE) {
        return 0;
      }
    }
  }

  return 1;
}

void assert_equals(int expected, int actual, const char *message) {
  if (expected != actual) {
    fprintf(stderr, "Assertion failed: %s\nExpected: %d\nActual: %d\n", message,
            expected, actual);
    exit(EXIT_FAILURE);
  }
}

void s_assert_equals(char *expected, char *actual, int len,
                     const char *message) {
  if (strncmp(expected, actual, len)) {
    fprintf(stderr, "Assertion failed: %s\nExpected: %s\nActual: %s\n", message,
            expected, actual);
    exit(EXIT_FAILURE);
  }
}

int test1() {
  sk_buf_t skb1 = {0};
  skb1.tot_len = hdr_len;

  sk_buf_t skb2 = {0};
  skb2.tot_len = hdr_len + 10;

  sk_buf_t skb3 = {0};
  skb3.tot_len = hdr_len + 5;

  sk_buf_t skb4 = {0};
  skb4.tot_len = hdr_len + 80;

  tc_http_ctx_t ctx = {
      .offset = 17,
      .seen = 0,
      .written = 0,
  };

  printf("Test 1\n");

  write_traceparent(&skb1, &ctx, (unsigned char *)TP);
  assert_equals(0, ctx.seen, "empty packet didn't move anything");

  write_traceparent(&skb2, &ctx, (unsigned char *)TP);
  assert_equals(10, ctx.seen, "seen 10 up");
  assert_equals(0, ctx.written, "written 0");

  write_traceparent(&skb3, &ctx, (unsigned char *)TP);
  assert_equals(15, ctx.seen, "seen 5 up");
  assert_equals(0, ctx.written, "written 0");

  write_traceparent(&skb4, &ctx, (unsigned char *)TP);
  assert_equals(ctx.offset, ctx.seen, "seen 2 up");
  assert_equals(EXTEND_SIZE, ctx.written, "written extend size");
  s_assert_equals((unsigned char *)TP, &skb4.data[ctx.offset - 15 + hdr_len],
                  EXTEND_SIZE, "data is in the right location and equal");

  printf("Worked!\n");
}

int test2() {
  sk_buf_t skb1 = {0};
  skb1.tot_len = hdr_len;

  sk_buf_t skb2 = {0};
  skb2.tot_len = hdr_len + 10;

  sk_buf_t skb3 = {0};
  skb3.tot_len = hdr_len + 25;

  sk_buf_t skb4 = {0};
  skb4.tot_len = hdr_len + 80;

  tc_http_ctx_t ctx = {
      .offset = 17,
      .seen = 0,
      .written = 0,
  };

  printf("Test 2\n");

  write_traceparent(&skb1, &ctx, (unsigned char *)TP);
  assert_equals(0, ctx.seen, "empty packet didn't move anything");

  write_traceparent(&skb2, &ctx, (unsigned char *)TP);
  assert_equals(10, ctx.seen, "seen 10 up");
  assert_equals(0, ctx.written, "written 0");

  write_traceparent(&skb3, &ctx, (unsigned char *)TP);
  assert_equals(ctx.offset, ctx.seen, "seen 25 up");
  assert_equals(25 - ctx.offset + 10, ctx.written, "written 0");
  s_assert_equals((unsigned char *)TP, &skb3.data[ctx.offset - 10 + hdr_len],
                  ctx.written, "data is in the right location and equal");

  unsigned int prev_written = ctx.written;

  write_traceparent(&skb4, &ctx, (unsigned char *)TP);
  assert_equals(ctx.offset, ctx.seen, "seen remains the same");
  assert_equals(EXTEND_SIZE, ctx.written, "written extend size");
  s_assert_equals((unsigned char *)TP + prev_written, &skb4.data[hdr_len],
                  EXTEND_SIZE - prev_written,
                  "data is in the right location and equal");

  printf("Worked!\n");
}

int test3() {
  sk_buf_t skb1 = {0};
  skb1.tot_len = hdr_len + 80;

  sk_buf_t skb2 = {0};
  skb2.tot_len = hdr_len + 80;

  tc_http_ctx_t ctx = {
      .offset = 17,
      .seen = 0,
      .written = 0,
  };

  printf("Test 3\n");

  write_traceparent(&skb1, &ctx, (unsigned char *)TP);
  assert_equals(ctx.offset, ctx.seen, "seen remains the same");
  assert_equals(80 - ctx.offset, ctx.written, "written extend size");
  s_assert_equals((unsigned char *)TP, &skb1.data[hdr_len + ctx.offset],
                  80 - ctx.offset, "data is in the right location and equal");

  unsigned int prev_written = ctx.written;

  write_traceparent(&skb2, &ctx, (unsigned char *)TP);
  assert_equals(ctx.offset, ctx.seen, "seen remains the same");
  assert_equals(EXTEND_SIZE, ctx.written, "written extend size");
  s_assert_equals((unsigned char *)TP + prev_written, &skb2.data[hdr_len],
                  EXTEND_SIZE - prev_written,
                  "data is in the right location and equal");

  printf("Worked!\n");
}

int test4() {
  sk_buf_t skb1 = {0};
  skb1.tot_len = hdr_len + 17;

  sk_buf_t skb2 = {0};
  skb2.tot_len = hdr_len + 80;

  tc_http_ctx_t ctx = {
      .offset = 17,
      .seen = 0,
      .written = 0,
  };

  printf("Test 4\n");

  write_traceparent(&skb1, &ctx, (unsigned char *)TP);
  assert_equals(ctx.offset, ctx.seen, "seen remains the same");
  assert_equals(0, ctx.written, "written 0");

  write_traceparent(&skb2, &ctx, (unsigned char *)TP);
  assert_equals(ctx.offset, ctx.seen, "seen remains the same");
  assert_equals(EXTEND_SIZE, ctx.written, "written extend size");
  s_assert_equals((unsigned char *)TP, &skb2.data[hdr_len], EXTEND_SIZE,
                  "data is in the right location and equal");

  printf("Worked!\n");
}

int test5() {
  sk_buf_t skb1 = {0};
  skb1.tot_len = hdr_len + 150;

  tc_http_ctx_t ctx = {
      .offset = 17,
      .seen = 0,
      .written = 0,
  };

  printf("Test 5\n");

  write_traceparent(&skb1, &ctx, (unsigned char *)TP);
  assert_equals(ctx.offset, ctx.seen, "seen remains the same");
  assert_equals(EXTEND_SIZE, ctx.written, "written extend size");
  s_assert_equals((unsigned char *)TP, &skb1.data[hdr_len + ctx.offset],
                  EXTEND_SIZE, "data is in the right location and equal");

  printf("Worked!\n");
}

int test6() {
  sk_buf_t skb1 = {0};
  skb1.tot_len = hdr_len;

  sk_buf_t skb2 = {0};
  skb2.tot_len = hdr_len + 10;

  sk_buf_t skb3 = {0};
  skb3.tot_len = hdr_len + 7;

  sk_buf_t skb4 = {0};
  skb4.tot_len = hdr_len + 80;

  tc_http_ctx_t ctx = {
      .offset = 17,
      .seen = 0,
      .written = 0,
  };

  printf("Test 6\n");

  write_traceparent(&skb1, &ctx, (unsigned char *)TP);
  assert_equals(0, ctx.seen, "empty packet didn't move anything");

  write_traceparent(&skb2, &ctx, (unsigned char *)TP);
  assert_equals(10, ctx.seen, "seen 10 up");
  assert_equals(0, ctx.written, "written 0");

  write_traceparent(&skb3, &ctx, (unsigned char *)TP);
  assert_equals(ctx.offset, ctx.seen, "seen 7 up");
  assert_equals(0, ctx.written, "written 0");

  write_traceparent(&skb4, &ctx, (unsigned char *)TP);
  assert_equals(ctx.offset, ctx.seen, "seen 0 up");
  assert_equals(EXTEND_SIZE, ctx.written, "written extend size");
  s_assert_equals((unsigned char *)TP, &skb4.data[hdr_len], EXTEND_SIZE,
                  "data is in the right location and equal");

  printf("Worked!\n");
}

int main(int argc, char **argv) {
  test1();
  test2();
  test3();
  test4();
  test5();
  test6();
}
