/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class BytesWithLenTest {

  @Test
  void testConstructorAndFields() {
    byte[] data = {1, 2, 3, 4};
    int len = 4;
    BytesWithLen bwl = new BytesWithLen(data, len);

    assertSame(data, bwl.buf, "Buffer reference should match");
    assertEquals(len, bwl.len, "Length should match");
  }

  @Test
  void testEmptyBuffer() {
    byte[] data = {};
    int len = 0;
    BytesWithLen bwl = new BytesWithLen(data, len);

    assertSame(data, bwl.buf);
    assertEquals(0, bwl.len);
  }

  @Test
  void testNullBuffer() {
    BytesWithLen bwl = new BytesWithLen(null, 0);
    assertNull(bwl.buf);
    assertEquals(0, bwl.len);
  }
}
