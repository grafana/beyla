/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static org.junit.jupiter.api.Assertions.*;

import java.net.InetAddress;
import org.junit.jupiter.api.Test;

class ConnectionTest {

  @Test
  void testConstructorAndGetters() throws Exception {
    InetAddress local = InetAddress.getByName("127.0.0.1");
    InetAddress remote = InetAddress.getByName("192.168.1.1");
    int localPort = 1234;
    int remotePort = 5678;

    Connection c = new Connection(local, localPort, remote, remotePort);

    assertEquals(local, c.getLocalAddress());
    assertEquals(localPort, c.getLocalPort());
    assertEquals(remote, c.getRemoteAddress());
    assertEquals(remotePort, c.getRemotePort());
    assertNull(c.getBufferKey());
  }

  @Test
  void testSetAndGetBufferKey() throws Exception {
    Connection c =
        new Connection(
            InetAddress.getByName("1.2.3.4"), 1111, InetAddress.getByName("5.6.7.8"), 2222);
    assertNull(c.getBufferKey());
    c.setBufferKey("key123");
    assertEquals("key123", c.getBufferKey());
  }

  @Test
  void testEqualsAndHashCode() throws Exception {
    InetAddress local = InetAddress.getByName("127.0.0.1");
    InetAddress remote = InetAddress.getByName("192.168.1.1");
    Connection c1 = new Connection(local, 1234, remote, 5678);
    Connection c2 = new Connection(local, 1234, remote, 5678);
    Connection c3 = new Connection(local, 1234, remote, 9999);

    assertEquals(c1, c2);
    assertEquals(c1.hashCode(), c2.hashCode());
    assertNotEquals(c1, c3);
    assertNotEquals(c1.hashCode(), c3.hashCode());

    // bufferKey does not affect equality
    c1.setBufferKey("foo");
    c2.setBufferKey("bar");
    assertEquals(c1, c2);
  }

  @Test
  void testNotEqualsNullOrOtherClass() throws Exception {
    InetAddress local = InetAddress.getByName("127.0.0.1");
    InetAddress remote = InetAddress.getByName("192.168.1.1");
    Connection c = new Connection(local, 1234, remote, 5678);

    assertNotEquals(c, null);
    assertNotEquals(c, "not a connection");
  }
}
