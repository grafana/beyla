/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.util;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;

class ByteBufferExtractorTest {

  @Test
  void testFlattenUsedByteBufferArray_NullInput() {
    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(null, 10);
    assertEquals(0, result.position());
    assertEquals(Math.min(10, ByteBufferExtractor.MAX_SIZE), result.capacity());
  }

  @Test
  void testFlattenUsedByteBufferArray_EmptyArray() {
    ByteBuffer[] buffers = new ByteBuffer[0];
    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(buffers, 10);
    assertEquals(0, result.position());
    assertEquals(Math.min(10, ByteBufferExtractor.MAX_SIZE), result.capacity());
  }

  @Test
  void testFlattenUsedByteBufferArray_SingleBuffer_FitsExactly() {
    ByteBuffer buf = ByteBuffer.allocate(5);
    buf.put(new byte[] {1, 2, 3, 4, 5});
    ByteBuffer[] buffers = new ByteBuffer[] {buf};

    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(buffers, 5);
    assertEquals(5, buf.position()); // original buffer position unchanged

    result.flip();
    byte[] out = new byte[5];
    result.get(out);
    assertArrayEquals(new byte[] {1, 2, 3, 4, 5}, out);
  }

  @Test
  void testFlattenUsedByteBufferArray_SingleBuffer_PartialCopy() {
    ByteBuffer buf = ByteBuffer.allocate(10);
    buf.put(new byte[] {10, 20, 30, 40, 50, 60, 70, 80, 90, 100});
    ByteBuffer[] buffers = new ByteBuffer[] {buf};

    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(buffers, 4);
    assertEquals(10, buf.position());

    result.flip();
    byte[] out = new byte[4];
    result.get(out);
    assertArrayEquals(new byte[] {10, 20, 30, 40}, out);
  }

  @Test
  void testFlattenUsedByteBufferArray_MultipleBuffers_ExactFit() {
    ByteBuffer buf1 = ByteBuffer.allocate(3);
    buf1.put(new byte[] {1, 2, 3});
    ByteBuffer buf2 = ByteBuffer.allocate(2);
    buf2.put(new byte[] {4, 5});
    ByteBuffer[] buffers = new ByteBuffer[] {buf1, buf2};

    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(buffers, 5);
    assertEquals(3, buf1.position());
    assertEquals(2, buf2.position());

    result.flip();
    byte[] out = new byte[5];
    result.get(out);
    assertArrayEquals(new byte[] {1, 2, 3, 4, 5}, out);
  }

  @Test
  void testFlattenUsedByteBufferArray_MultipleBuffers_OverflowsLast() {
    ByteBuffer buf1 = ByteBuffer.allocate(3);
    buf1.put(new byte[] {1, 2, 3});
    ByteBuffer buf2 = ByteBuffer.allocate(ByteBufferExtractor.MAX_SIZE);
    byte[] buf = new byte[ByteBufferExtractor.MAX_SIZE];
    for (int i = 0; i < ByteBufferExtractor.MAX_SIZE; i++) {
      buf[i] = (byte) (i % 256);
    }
    buf2.put(buf);
    buf2.position(ByteBufferExtractor.MAX_SIZE);
    buf2.limit(ByteBufferExtractor.MAX_SIZE); // only bytes 50, 60
    ByteBuffer[] buffers = new ByteBuffer[] {buf1, buf2};

    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(buffers, 5);
    assertEquals(3, buf1.position());
    assertEquals(ByteBufferExtractor.MAX_SIZE, buf2.position());

    result.flip();
    byte[] out = new byte[5];
    result.get(out);
    assertArrayEquals(new byte[] {1, 2, 3, 0, 1}, out);
  }

  @Test
  void testFlattenUsedByteBufferArray_MultipleBuffers_PartialLastBuffer() {
    ByteBuffer buf1 = ByteBuffer.allocate(3);
    buf1.put(new byte[] {1, 2, 3});
    ByteBuffer buf2 = ByteBuffer.allocate(4);
    buf2.put(new byte[] {4, 5, 6, 7});
    ByteBuffer[] buffers = new ByteBuffer[] {buf1, buf2};
    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(buffers, 5);
    assertEquals(3, buf1.position());
    assertEquals(4, buf2.position());

    result.flip();
    byte[] out = new byte[5];
    result.get(out);
    assertArrayEquals(new byte[] {1, 2, 3, 4, 5}, out);
  }

  @Test
  void testFlattenUsedByteBufferArray_BufferWithNonZeroPosition() {
    ByteBuffer buf = ByteBuffer.allocate(6);
    buf.put(new byte[] {10, 20, 30, 40, 50, 60});
    buf.position(3); // simulate buffer with position not at 0
    ByteBuffer[] buffers = new ByteBuffer[] {buf};
    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(buffers, 3);
    assertEquals(3, buf.position()); // original buffer position unchanged

    result.flip();
    byte[] out = new byte[3];
    result.get(out);
    assertArrayEquals(new byte[] {10, 20, 30}, out);
  }

  @Test
  void testFlattenUsedByteBufferArray_LimitGreaterThanLen() {
    ByteBuffer buf1 = ByteBuffer.allocate(10);
    buf1.put(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10});
    ByteBuffer buf2 = ByteBuffer.allocate(10);
    buf2.put(new byte[] {11, 12, 13, 14, 15, 16, 17, 18, 19, 20});
    ByteBuffer[] buffers = new ByteBuffer[] {buf1, buf2};

    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(buffers, 12);
    assertEquals(10, buf1.position());
    assertEquals(10, buf2.position());

    result.flip();
    byte[] out = new byte[12];
    result.get(out);
    assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, out);
  }

  @Test
  void testFlattenUsedByteBufferArray_LenGreaterThanMaxSize() {
    ByteBuffer buf = ByteBuffer.allocate(2000);
    for (int i = 0; i < 2000; i++) {
      buf.put((byte) (i % 128));
    }
    ByteBuffer[] buffers = new ByteBuffer[] {buf};
    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(buffers, 2000);
    assertEquals(2000, buf.position());

    assertEquals(ByteBufferExtractor.MAX_SIZE, result.capacity());

    result.flip();
    for (int i = 0; i < ByteBufferExtractor.MAX_SIZE; i++) {
      assertEquals((byte) (i % 128), result.get());
    }
  }

  @Test
  void testFlattenUsedByteBufferArray_WithNullBufferInArray() {
    ByteBuffer buf1 = ByteBuffer.allocate(3);
    buf1.put(new byte[] {1, 2, 3});
    ByteBuffer buf2 = null;
    ByteBuffer buf3 = ByteBuffer.allocate(2);
    buf3.put(new byte[] {4, 5});
    ByteBuffer[] buffers = new ByteBuffer[] {buf1, buf2, buf3};

    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(buffers, 5);
    assertEquals(3, buf1.position());
    assertEquals(2, buf3.position());

    result.flip();
    byte[] out = new byte[5];
    result.get(out);
    assertArrayEquals(new byte[] {1, 2, 3, 4, 5}, out);
  }

  @Test
  void testFlattenUsedByteBufferArray_WithMultipleNullBuffers() {
    ByteBuffer buf1 = null;
    ByteBuffer buf2 = ByteBuffer.allocate(3);
    buf2.put(new byte[] {10, 20, 30});
    ByteBuffer buf3 = null;
    ByteBuffer buf4 = ByteBuffer.allocate(2);
    buf4.put(new byte[] {40, 50});
    ByteBuffer buf5 = null;
    ByteBuffer[] buffers = new ByteBuffer[] {buf1, buf2, buf3, buf4, buf5};

    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(buffers, 5);
    assertEquals(3, buf2.position());
    assertEquals(2, buf4.position());

    result.flip();
    byte[] out = new byte[5];
    result.get(out);
    assertArrayEquals(new byte[] {10, 20, 30, 40, 50}, out);
  }

  @Test
  void testFlattenUsedByteBufferArray_AllNullBuffers() {
    ByteBuffer[] buffers = new ByteBuffer[] {null, null, null};

    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(buffers, 10);
    assertEquals(0, result.position());
    assertEquals(10, result.capacity());
  }

  @Test
  void testFlattenFreshByteBufferArray_NullInput() {
    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(null);
    assertEquals(0, result.position());
    assertEquals(ByteBufferExtractor.MAX_SIZE, result.capacity());
  }

  @Test
  void testFlattenFreshByteBufferArray_EmptyArray() {
    ByteBuffer[] srcs = new ByteBuffer[0];
    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
    assertEquals(0, result.position());
    assertEquals(ByteBufferExtractor.MAX_SIZE, result.capacity());
  }

  @Test
  void testFlattenFreshByteBufferArray_SingleBuffer_FullCopy() {
    ByteBuffer buf = ByteBuffer.allocate(5);
    buf.put(new byte[] {1, 2, 3, 4, 5});
    buf.position(1);
    ByteBuffer[] srcs = new ByteBuffer[] {buf};

    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
    assertEquals(5, buf.limit());
    assertEquals(1, buf.position());

    result.flip();
    byte[] out = new byte[result.limit()];
    result.get(out);
    assertArrayEquals(new byte[] {2, 3, 4, 5}, out);
  }

  @Test
  void testFlattenFreshByteBufferArray_SingleBuffer_PartialCopy() {
    ByteBuffer buf = ByteBuffer.allocate(10);
    buf.position(2);
    buf.limit(7);
    for (int i = 2; i < 7; i++) {
      buf.put(i, (byte) (i + 10));
    }
    ByteBuffer[] srcs = new ByteBuffer[] {buf};

    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
    assertEquals(2, buf.position());
    assertEquals(7, buf.limit());

    result.flip();
    byte[] out = new byte[5];
    result.get(out);
    assertArrayEquals(new byte[] {12, 13, 14, 15, 16}, out);
  }

  @Test
  void testFlattenFreshByteBufferArray_MultipleBuffers_ExactFit() {
    ByteBuffer buf1 = ByteBuffer.allocate(3);
    buf1.put(new byte[] {1, 2, 3});
    buf1.flip();
    ByteBuffer buf2 = ByteBuffer.allocate(3);
    buf2.put(new byte[] {4, 5, 6});
    buf2.position(1);
    ByteBuffer[] srcs = new ByteBuffer[] {buf1, buf2};

    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
    assertEquals(0, buf1.position());
    assertEquals(3, buf1.limit());
    assertEquals(1, buf2.position());
    assertEquals(3, buf2.limit());

    result.flip();
    byte[] out = new byte[5];
    result.get(out);
    assertArrayEquals(new byte[] {1, 2, 3, 5, 6}, out);
  }

  @Test
  void testFlattenFreshByteBufferArray_MultipleBuffers_PartialLastBuffer() {
    ByteBuffer buf1 = ByteBuffer.allocate(3);
    buf1.put(new byte[] {10, 20, 30});
    buf1.flip();
    ByteBuffer buf2 = ByteBuffer.allocate(4);
    buf2.put(new byte[] {40, 50, 60, 70});
    buf2.position(1);
    buf2.limit(3); // only bytes 50, 60
    ByteBuffer[] srcs = new ByteBuffer[] {buf1, buf2};

    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
    assertEquals(0, buf1.position());
    assertEquals(3, buf1.limit());
    assertEquals(1, buf2.position());
    assertEquals(3, buf2.limit());

    result.flip();
    byte[] out = new byte[5];
    result.get(out);
    assertArrayEquals(new byte[] {10, 20, 30, 50, 60}, out);
  }

  @Test
  void testFlattenFreshByteBufferArray_MultipleBuffers_OverflowsLast() {
    ByteBuffer buf1 = ByteBuffer.allocate(3);
    buf1.put(new byte[] {10, 20, 30});
    buf1.flip();
    ByteBuffer buf2 = ByteBuffer.allocate(ByteBufferExtractor.MAX_SIZE);
    byte[] buf = new byte[ByteBufferExtractor.MAX_SIZE];
    for (int i = 0; i < ByteBufferExtractor.MAX_SIZE; i++) {
      buf[i] = (byte) (i % 256);
    }
    buf2.put(buf);
    buf2.position(0);
    buf2.limit(ByteBufferExtractor.MAX_SIZE); // only bytes 50, 60
    ByteBuffer[] srcs = new ByteBuffer[] {buf1, buf2};

    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
    assertEquals(0, buf1.position());
    assertEquals(3, buf1.limit());
    assertEquals(0, buf2.position());
    assertEquals(ByteBufferExtractor.MAX_SIZE, buf2.limit());

    result.flip();
    byte[] out = new byte[5];
    result.get(out);
    assertArrayEquals(new byte[] {10, 20, 30, 0, 1}, out);
  }

  @Test
  void testFlattenFreshByteBufferArray_BufferWithNonZeroPosition() {
    ByteBuffer buf = ByteBuffer.allocate(6);
    buf.put(new byte[] {10, 20, 30, 40, 50, 60});
    buf.position(2);
    buf.limit(5); // bytes 30, 40, 50
    ByteBuffer[] srcs = new ByteBuffer[] {buf};

    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
    assertEquals(2, buf.position());
    assertEquals(5, buf.limit());

    result.flip();
    byte[] out = new byte[3];
    result.get(out);
    assertArrayEquals(new byte[] {30, 40, 50}, out);
  }

  @Test
  void testFlattenFreshByteBufferArray_LimitGreaterThanMaxSize() {
    ByteBuffer buf1 = ByteBuffer.allocate(2000);
    for (int i = 0; i < 2000; i++) {
      buf1.put((byte) (i % 128));
    }
    buf1.flip();
    ByteBuffer[] srcs = new ByteBuffer[] {buf1};

    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
    assertEquals(ByteBufferExtractor.MAX_SIZE, result.capacity());
    result.flip();
    for (int i = 0; i < ByteBufferExtractor.MAX_SIZE; i++) {
      assertEquals((byte) (i % 128), result.get());
    }
    assertEquals(0, buf1.position());
    assertEquals(2000, buf1.limit());
  }

  @Test
  void testFlattenFreshByteBufferArray_MultipleBuffers_ExceedMaxSize() {
    ByteBuffer buf1 = ByteBuffer.allocate(800);
    ByteBuffer buf2 = ByteBuffer.allocate(800);
    for (int i = 0; i < 800; i++) {
      buf1.put((byte) (i + 1));
      buf2.put((byte) (i + 101));
    }
    buf1.position(1);
    buf2.flip();
    ByteBuffer[] srcs = new ByteBuffer[] {buf1, buf2};

    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
    assertEquals(ByteBufferExtractor.MAX_SIZE, result.capacity());
    result.flip();
    for (int i = 1; i < 800; i++) {
      assertEquals((byte) (i + 1), result.get());
    }
    for (int i = 0; i < 224; i++) {
      assertEquals((byte) (i + 101), result.get());
    }
    assertEquals(1, buf1.position());
    assertEquals(800, buf1.limit());
    assertEquals(0, buf2.position());
    assertEquals(800, buf2.limit());
  }

  @Test
  void testFlattenFreshByteBufferArray_WithNullBufferInArray() {
    ByteBuffer buf1 = ByteBuffer.allocate(3);
    buf1.put(new byte[] {1, 2, 3});
    buf1.flip();
    ByteBuffer buf3 = ByteBuffer.allocate(3);
    buf3.put(new byte[] {4, 5, 6});
    buf3.position(1);
    ByteBuffer[] srcs = new ByteBuffer[] {buf1, null, buf3};

    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
    assertEquals(0, buf1.position());
    assertEquals(3, buf1.limit());
    assertEquals(1, buf3.position());
    assertEquals(3, buf3.limit());

    result.flip();
    byte[] out = new byte[5];
    result.get(out);
    assertArrayEquals(new byte[] {1, 2, 3, 5, 6}, out);
  }

  @Test
  void testFlattenFreshByteBufferArray_WithMultipleNullBuffers() {
    ByteBuffer buf2 = ByteBuffer.allocate(3);
    buf2.put(new byte[] {10, 20, 30});
    buf2.flip();
    ByteBuffer buf4 = ByteBuffer.allocate(2);
    buf4.put(new byte[] {40, 50});
    buf4.position(1);
    ByteBuffer[] srcs = new ByteBuffer[] {null, buf2, null, buf4, null};

    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
    assertEquals(0, buf2.position());
    assertEquals(3, buf2.limit());
    assertEquals(1, buf4.position());
    assertEquals(2, buf4.limit());

    result.flip();
    byte[] out = new byte[4];
    result.get(out);
    assertArrayEquals(new byte[] {10, 20, 30, 50}, out);
  }

  @Test
  void testFlattenFreshByteBufferArray_AllNullBuffers() {
    ByteBuffer[] srcs = new ByteBuffer[] {null, null, null};

    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(srcs);
    assertEquals(0, result.position());
    assertEquals(ByteBufferExtractor.MAX_SIZE, result.capacity());
  }

  @Test
  void testFromFreshBuffer_NullInput() {
    ByteBuffer result = ByteBufferExtractor.fromFreshBuffer(null, 10);
    assertEquals(0, result.position());
    assertEquals(0, result.capacity());
  }

  @Test
  void testFromFreshBufferArray_EmptyBuffer() {
    ByteBuffer src = ByteBuffer.allocate(0);
    ByteBuffer result = ByteBufferExtractor.fromFreshBuffer(src, 10);
    assertEquals(0, result.position());
    assertEquals(0, result.capacity());
    assertEquals(0, src.position());
    assertEquals(0, src.limit());
  }

  @Test
  void testFromFreshBufferArray_BufferSmallerThanLen() {
    ByteBuffer src = ByteBuffer.allocate(5);
    src.put(new byte[] {1, 2, 3, 4, 5});
    src.flip();
    ByteBuffer result = ByteBufferExtractor.fromFreshBuffer(src, 10);
    result.flip();
    byte[] out = new byte[5];
    result.get(out);
    assertArrayEquals(new byte[] {1, 2, 3, 4, 5}, out);
    assertEquals(0, src.position());
    assertEquals(5, src.limit());
  }

  @Test
  void testFromFreshBufferArray_BufferEqualToLen() {
    ByteBuffer src = ByteBuffer.allocate(4);
    src.put(new byte[] {9, 8, 7, 6});
    src.flip();
    ByteBuffer result = ByteBufferExtractor.fromFreshBuffer(src, 4);
    result.flip();
    byte[] out = new byte[4];
    result.get(out);
    assertArrayEquals(new byte[] {9, 8, 7, 6}, out);
    assertEquals(0, src.position());
    assertEquals(4, src.limit());
  }

  @Test
  void testFromFreshBufferArray_BufferGreaterThanLen() {
    ByteBuffer src = ByteBuffer.allocate(10);
    src.put(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10});
    src.position(2);
    src.limit(8); // bytes 3,4,5,6,7,8
    ByteBuffer result = ByteBufferExtractor.fromFreshBuffer(src, 4);
    result.flip();
    byte[] out = new byte[4];
    result.get(out);
    assertArrayEquals(new byte[] {3, 4, 5, 6}, out);
    assertEquals(2, src.position());
    assertEquals(8, src.limit());
  }

  @Test
  void testFromFreshBuffer_LenGreaterThanMaxSize() {
    ByteBuffer src = ByteBuffer.allocate(2000);
    for (int i = 0; i < 2000; i++) {
      src.put((byte) (i % 128));
    }
    src.flip();
    ByteBuffer result = ByteBufferExtractor.fromFreshBuffer(src, 2000);
    assertEquals(ByteBufferExtractor.MAX_SIZE, result.capacity());
    result.flip();
    for (int i = 0; i < ByteBufferExtractor.MAX_SIZE; i++) {
      assertEquals((byte) (i % 128), result.get());
    }
    assertEquals(0, src.position());
    assertEquals(2000, src.limit());
  }

  @Test
  void testFromFreshBufferArray_BufferWithNonZeroPositionAndLimit() {
    ByteBuffer src = ByteBuffer.allocate(10);
    src.put(new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9});
    src.position(3);
    src.limit(8); // bytes 3,4,5,6,7
    ByteBuffer result = ByteBufferExtractor.fromFreshBuffer(src, 10);
    result.flip();
    byte[] out = new byte[5];
    result.get(out);
    assertArrayEquals(new byte[] {3, 4, 5, 6, 7}, out);
    assertEquals(3, src.position());
    assertEquals(8, src.limit());
  }

  @Test
  void testFromFreshBuffer_LenZero() {
    ByteBuffer src = ByteBuffer.allocate(5);
    src.put(new byte[] {1, 2, 3, 4, 5});
    src.flip();
    ByteBuffer result = ByteBufferExtractor.fromFreshBuffer(src, 0);
    assertEquals(0, result.capacity());
    assertEquals(0, result.position());
    assertEquals(0, src.position());
    assertEquals(5, src.limit());
  }

  @Test
  void testBufferKeyEmptyBuffer() {
    ByteBuffer buf = ByteBuffer.allocate(0);
    assertEquals("[]", ByteBufferExtractor.keyFromUsedBuffer(buf));
  }

  @Test
  void testBufferKeyLessThanMaxKeySize() {
    ByteBuffer buf = ByteBuffer.allocate(10);
    for (int i = 0; i < 10; i++) buf.put((byte) i);
    // position is 10, so keySize = 10
    String expected = "[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]";
    assertEquals(expected, ByteBufferExtractor.keyFromUsedBuffer(buf));
    // After call, position and limit should be unchanged
    assertEquals(10, buf.position());
    assertEquals(10, buf.limit());
  }

  @Test
  void testBufferKeyEqualToMaxKeySize() {
    ByteBuffer buf = ByteBuffer.allocate(ByteBufferExtractor.MAX_KEY_SIZE);
    for (int i = 0; i < ByteBufferExtractor.MAX_KEY_SIZE; i++) buf.put((byte) (i + 1));
    StringBuilder sb = new StringBuilder("[");
    for (int i = 0; i < ByteBufferExtractor.MAX_KEY_SIZE; i++) {
      sb.append(i + 1);
      if (i < ByteBufferExtractor.MAX_KEY_SIZE - 1) sb.append(", ");
    }
    sb.append("]");
    assertEquals(sb.toString(), ByteBufferExtractor.keyFromUsedBuffer(buf));
    assertEquals(ByteBufferExtractor.MAX_KEY_SIZE, buf.position());
    assertEquals(ByteBufferExtractor.MAX_KEY_SIZE, buf.limit());
  }

  @Test
  void testBufferKeyGreaterThanMaxKeySize() {
    int size = ByteBufferExtractor.MAX_KEY_SIZE + 10;
    ByteBuffer buf = ByteBuffer.allocate(size);
    for (int i = 0; i < size; i++) buf.put((byte) (i + 2));
    // Only first MAX_KEY_SIZE bytes should be used
    StringBuilder sb = new StringBuilder("[");
    for (int i = 0; i < ByteBufferExtractor.MAX_KEY_SIZE; i++) {
      sb.append(i + 2);
      if (i < ByteBufferExtractor.MAX_KEY_SIZE - 1) sb.append(", ");
    }
    sb.append("]");
    assertEquals(sb.toString(), ByteBufferExtractor.keyFromUsedBuffer(buf));
    assertEquals(size, buf.position());
    assertEquals(size, buf.limit());
  }

  @Test
  void testSrcBufferKeyEmptyBuffer() {
    ByteBuffer buf = ByteBuffer.allocate(0);
    assertEquals("[]", ByteBufferExtractor.keyFromFreshBuffer(buf));
  }

  @Test
  void testSrcBufferKeyLessThanMaxKeySize() {
    ByteBuffer buf = ByteBuffer.allocate(10);
    for (int i = 0; i < 10; i++) buf.put((byte) (i + 10));
    buf.flip(); // position=0, limit=10
    buf.position(2); // simulate reading 2 bytes
    // remaining = 8, keySize = 8
    String expected = "[12, 13, 14, 15, 16, 17, 18, 19]";
    assertEquals(expected, ByteBufferExtractor.keyFromFreshBuffer(buf));
    // After call, position and limit should be unchanged
    assertEquals(2, buf.position());
    assertEquals(10, buf.limit());
  }

  @Test
  void testSrcBufferKeyEqualToMaxKeySize() {
    ByteBuffer buf = ByteBuffer.allocate(ByteBufferExtractor.MAX_KEY_SIZE + 5);
    for (int i = 0; i < ByteBufferExtractor.MAX_KEY_SIZE + 5; i++) buf.put((byte) (i + 20));
    buf.flip();
    buf.position(5); // remaining = MAX_KEY_SIZE
    StringBuilder sb = new StringBuilder("[");
    for (int i = 0; i < ByteBufferExtractor.MAX_KEY_SIZE; i++) {
      sb.append(i + 25);
      if (i < ByteBufferExtractor.MAX_KEY_SIZE - 1) sb.append(", ");
    }
    sb.append("]");
    assertEquals(sb.toString(), ByteBufferExtractor.keyFromFreshBuffer(buf));
    assertEquals(5, buf.position());
    assertEquals(ByteBufferExtractor.MAX_KEY_SIZE + 5, buf.limit());
  }

  @Test
  void testSrcBufferKeyGreaterThanMaxKeySize() {
    int size = ByteBufferExtractor.MAX_KEY_SIZE + 10;
    ByteBuffer buf = ByteBuffer.allocate(size);
    for (int i = 0; i < size; i++) buf.put((byte) (i + 30));
    buf.flip();
    buf.position(5); // remaining = MAX_KEY_SIZE + 5
    // Only MAX_KEY_SIZE bytes from position 5
    StringBuilder sb = new StringBuilder("[");
    for (int i = 0; i < ByteBufferExtractor.MAX_KEY_SIZE; i++) {
      sb.append(i + 35);
      if (i < ByteBufferExtractor.MAX_KEY_SIZE - 1) sb.append(", ");
    }
    sb.append("]");
    assertEquals(sb.toString(), ByteBufferExtractor.keyFromFreshBuffer(buf));
    assertEquals(5, buf.position());
    assertEquals(size, buf.limit());
  }
}
