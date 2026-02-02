/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.jna.Pointer;
import io.opentelemetry.obi.java.Agent;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.Socket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ProxyInputStreamTest {
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
    ProxyInputStream.instance = new MockCLibrary();
  }

  @Test
  void testReadSingleByte() throws IOException {
    byte[] data = {42};
    ProxyInputStream pis = new ProxyInputStream(new ByteArrayInputStream(data), new Socket());
    byte[] buffer = new byte[1];
    int value = pis.read(buffer);
    assertEquals(1, value);
    assertArrayEquals(data, buffer);
    pis.close();
    assertEquals(2, p.getByte(0));
    assertEquals(1, p.getInt(1 + 36));
    assertEquals(42, p.getByte(1 + 36 + 4));
  }

  @Test
  void testReadByteArray() throws IOException {
    byte[] data = {1, 2, 3, 4};
    byte[] buffer = new byte[4];
    ProxyInputStream pis = new ProxyInputStream(new ByteArrayInputStream(data), new Socket());
    int len = pis.read(buffer);
    assertEquals(4, len);
    assertArrayEquals(data, buffer);
    pis.close();
    assertEquals(2, p.getByte(0));
    assertEquals(data.length, p.getInt(1 + 36));
    assertArrayEquals(data, p.getByteArray(1 + 36 + 4, data.length));
  }

  @Test
  void testReadByteArrayWithOffset() throws IOException {
    byte[] data = {10, 20, 30, 40};
    byte[] buffer = new byte[6];
    ProxyInputStream pis = new ProxyInputStream(new ByteArrayInputStream(data), new Socket());
    int len = pis.read(buffer, 1, 4);
    assertEquals(4, len);
    assertArrayEquals(new byte[] {0, 10, 20, 30, 40, 0}, buffer);
    pis.close();
    assertEquals(2, p.getByte(0));
    assertEquals(data.length, p.getInt(1 + 36));
    assertArrayEquals(data, p.getByteArray(1 + 36 + 4, data.length));
  }
}
