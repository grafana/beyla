/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.util;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class ByteBufferExtractor {
  public static final int MAX_SIZE = 1024;
  public static final int MAX_KEY_SIZE = 64;

  // This deals with buffers that have already been consumed, as in, the data we
  // want is from the start of the buffer up to the position.
  public static ByteBuffer flattenUsedByteBufferArray(ByteBuffer[] dsts, int len) {
    ByteBuffer dstBuffer = ByteBuffer.allocate(Math.min(len, MAX_SIZE));
    if (dsts == null) {
      return dstBuffer;
    }
    int consumed = 0;
    for (int i = 0; i < dsts.length && consumed <= ((java.nio.Buffer) dstBuffer).limit(); i++) {
      // Skip null buffers
      if (dsts[i] == null) {
        continue;
      }
      // we want to read 0 -> oldPos, save the existing state
      int oldPos = ((java.nio.Buffer) dsts[i]).position();
      int oldLimit = ((java.nio.Buffer) dsts[i]).limit();
      // move pos -> 0 and limit -> oldPos
      ((java.nio.Buffer) dsts[i]).flip();

      if (((java.nio.Buffer) dsts[i]).remaining() <= ((java.nio.Buffer) dstBuffer).remaining()) {
        dstBuffer.put(dsts[i]);
      } else {
        ByteBuffer slice = dsts[i].slice();
        slice.limit(
            Math.min(
                ((java.nio.Buffer) slice).remaining(), ((java.nio.Buffer) dstBuffer).remaining()));
        dstBuffer.put(slice);
      }
      ((java.nio.Buffer) dsts[i]).position(oldPos);
      ((java.nio.Buffer) dsts[i]).limit(oldLimit);
      // we'd read the full size (up to oldPos) or partial. It's ok to boost the
      // consumed value by oldPos, since we'll be done with the loop anyway if we
      // read up to the max.
      consumed += oldPos;
    }

    return dstBuffer;
  }

  // This deals with buffers that are about to be read, they are freshly made for
  // the Java program to consume. We want to read from their pos to the limit.
  public static ByteBuffer flattenFreshByteBufferArray(ByteBuffer[] srcs) {
    ByteBuffer dstBuffer = ByteBuffer.allocate(MAX_SIZE);
    if (srcs == null) {
      return dstBuffer;
    }
    int consumed = 0;
    for (int i = 0; i < srcs.length && consumed <= ((java.nio.Buffer) dstBuffer).limit(); i++) {
      // Skip null buffers
      if (srcs[i] == null) {
        continue;
      }
      // save the prior values
      int oldPos = ((java.nio.Buffer) srcs[i]).position();
      int oldLimit = ((java.nio.Buffer) srcs[i]).limit();
      // the remaining = limit - pos is how much we'll consume, unless the
      // destination buffer will fill up to the max.
      int remaining = ((java.nio.Buffer) srcs[i]).remaining();

      if (((java.nio.Buffer) srcs[i]).remaining() <= ((java.nio.Buffer) dstBuffer).remaining()) {
        dstBuffer.put(srcs[i]);
      } else {
        ByteBuffer slice = srcs[i].slice();
        ((java.nio.Buffer) slice)
            .limit(
                Math.min(
                    ((java.nio.Buffer) slice).remaining(),
                    ((java.nio.Buffer) dstBuffer).remaining()));
        dstBuffer.put(slice);
      }
      // restore the state
      ((java.nio.Buffer) srcs[i]).position(oldPos);
      ((java.nio.Buffer) srcs[i]).limit(oldLimit);
      // bump the consumed by the original remaining, if we partially read we are
      // fine with over calculating, since we'll be done with the loop.
      consumed += remaining;
    }

    return dstBuffer;
  }

  // this is same as flattenFreshByteBufferArray, except we read only one buffer.
  public static ByteBuffer fromFreshBuffer(ByteBuffer src, int len) {
    int bufSize =
        (src == null) ? 0 : Math.min(((java.nio.Buffer) src).remaining(), Math.min(len, MAX_SIZE));
    ByteBuffer dstBuffer = ByteBuffer.allocate(bufSize);
    if (src != null) {
      // save state
      int oldPos = ((java.nio.Buffer) src).position();
      int oldLimit = ((java.nio.Buffer) src).limit();
      // make a slice so that we can add limit to the max copied size
      ByteBuffer slice = src.slice();
      ((java.nio.Buffer) slice).limit(bufSize);
      dstBuffer.put(slice);
      // restore the position
      ((java.nio.Buffer) src).position(oldPos);
      ((java.nio.Buffer) src).limit(oldLimit);
    }

    return dstBuffer;
  }

  // same concept as reading used bytes, except we produce a string from
  // the values that we'll be using as unique keys
  public static String keyFromUsedBuffer(ByteBuffer buf) {
    int oldPosition = ((java.nio.Buffer) buf).position();
    int oldLimit = ((java.nio.Buffer) buf).limit();

    // we'll be reading 0 -> oldPosition
    int keySize = Math.min(((java.nio.Buffer) buf).position(), MAX_KEY_SIZE);
    // move pos -> 0 and limit -> oldPos
    ((java.nio.Buffer) buf).flip();
    byte[] bytes = new byte[keySize];
    buf.get(bytes);

    // restore the state
    ((java.nio.Buffer) buf).position(oldPosition);
    ((java.nio.Buffer) buf).limit(oldLimit);

    return Arrays.toString(bytes);
  }

  // same concept as reading fresh (unconsumed) bytes, except we produce a string from
  // the values that we'll be using as unique keys
  public static String keyFromFreshBuffer(ByteBuffer buf) {
    int oldPosition = ((java.nio.Buffer) buf).position();
    int oldLimit = ((java.nio.Buffer) buf).limit();

    // we are reading position -> limit
    int keySize = Math.min(((java.nio.Buffer) buf).remaining(), MAX_KEY_SIZE);
    byte[] bytes = new byte[keySize];
    buf.get(bytes);

    // restore state
    ((java.nio.Buffer) buf).position(oldPosition);
    ((java.nio.Buffer) buf).limit(oldLimit);

    return Arrays.toString(bytes);
  }
}
