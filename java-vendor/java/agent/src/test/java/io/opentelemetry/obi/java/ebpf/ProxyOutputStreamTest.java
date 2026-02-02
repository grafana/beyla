/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.jna.Pointer;
import io.opentelemetry.obi.java.Agent;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ProxyOutputStreamTest {
  static Pointer p = null;

  static class MockCLibrary implements Agent.CLibrary {
    @Override
    public int ioctl(int a, int b, long c) {
      p = new Pointer(c);
      return 0;
    }

    public int gettid() {
      return 1;
    }
  }

  @BeforeEach
  void setUp() {
    ProxyOutputStream.instance = new MockCLibrary();
  }

  @Test
  void testWriteSingleByte() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ProxyOutputStream pos = new ProxyOutputStream(baos, new Socket());
    pos.write(new byte[] {42});
    pos.close();
    assertArrayEquals(new byte[] {42}, baos.toByteArray());

    assertEquals(1, p.getByte(0));
    assertEquals(1, p.getInt(1 + 36));
    assertEquals(42, p.getByte(1 + 36 + 4));
  }

  @Test
  void testWriteByteArray() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ProxyOutputStream pos = new ProxyOutputStream(baos, new Socket());
    byte[] data = {1, 2, 3, 4};
    pos.write(data);
    pos.close();
    assertArrayEquals(data, baos.toByteArray());
    assertEquals(1, p.getByte(0));
    assertEquals(data.length, p.getInt(1 + 36));
    assertArrayEquals(data, p.getByteArray(1 + 36 + 4, data.length));
  }

  @Test
  void testWriteByteArrayWithOffset() throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    ProxyOutputStream pos = new ProxyOutputStream(baos, new Socket());
    byte[] data = {10, 20, 30, 40, 50};
    pos.write(data, 1, 3); // Should write 20, 30, 40
    pos.close();
    assertArrayEquals(new byte[] {20, 30, 40}, baos.toByteArray());
    assertEquals(1, p.getByte(0));
    assertEquals(data.length, p.getInt(1 + 36));
    assertArrayEquals(data, p.getByteArray(1 + 36 + 4, data.length));
  }
}
