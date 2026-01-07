/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.util;

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.instrumentations.data.Connection;
import io.opentelemetry.obi.java.instrumentations.data.SSLStorage;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class NettyChannelExtractorTest {

  static class MockChannel {
    private final InetSocketAddress local;
    private final InetSocketAddress remote;

    MockChannel(InetSocketAddress local, InetSocketAddress remote) {
      this.local = local;
      this.remote = remote;
    }

    public InetSocketAddress localAddress() {
      return local;
    }

    public InetSocketAddress remoteAddress() {
      return remote;
    }
  }

  static class MockContext {
    private final MockChannel channel;

    MockContext(MockChannel channel) {
      this.channel = channel;
    }

    public MockChannel channel() {
      return channel;
    }
  }

  @AfterEach
  void resetDebug() {
    SSLStorage.debugOn = false;
  }

  @Test
  void testExtractConnectionNormal() throws Exception {
    InetSocketAddress local = new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 1234);
    InetSocketAddress remote = new InetSocketAddress(InetAddress.getByName("192.168.1.1"), 5678);
    MockChannel channel = new MockChannel(local, remote);
    MockContext ctx = new MockContext(channel);

    Connection c = NettyChannelExtractor.extractConnectionFromChannelHandlerContext(ctx);
    assertNotNull(c);
    assertEquals(local.getAddress(), c.getLocalAddress());
    assertEquals(local.getPort(), c.getLocalPort());
    assertEquals(remote.getAddress(), c.getRemoteAddress());
    assertEquals(remote.getPort(), c.getRemotePort());
  }

  @Test
  void testExtractConnectionWithDebug() throws Exception {
    SSLStorage.debugOn = true;
    InetSocketAddress local = new InetSocketAddress(InetAddress.getByName("127.0.0.2"), 4321);
    InetSocketAddress remote = new InetSocketAddress(InetAddress.getByName("10.0.0.1"), 8765);
    MockChannel channel = new MockChannel(local, remote);
    MockContext ctx = new MockContext(channel);

    Connection c = NettyChannelExtractor.extractConnectionFromChannelHandlerContext(ctx);
    assertNotNull(c);
    assertEquals(local.getAddress(), c.getLocalAddress());
    assertEquals(local.getPort(), c.getLocalPort());
    assertEquals(remote.getAddress(), c.getRemoteAddress());
    assertEquals(remote.getPort(), c.getRemotePort());
  }

  @Test
  void testExtractConnectionNullChannel() {
    Object ctx =
        new Object() {
          public Object channel() {
            return null;
          }
        };
    Connection c = NettyChannelExtractor.extractConnectionFromChannelHandlerContext(ctx);
    assertNull(c);
  }

  @Test
  void testExtractConnectionNullAddresses() {
    MockChannel channel = new MockChannel(null, null);
    MockContext ctx = new MockContext(channel);
    Connection c = NettyChannelExtractor.extractConnectionFromChannelHandlerContext(ctx);
    assertThrows(
        NullPointerException.class,
        () -> {
          // Accessing address/port will throw
          c.getLocalAddress();
        });
  }

  @Test
  void testExtractConnectionExceptionHandling() {
    Object badCtx = new Object(); // No channel() method
    Connection c = NettyChannelExtractor.extractConnectionFromChannelHandlerContext(badCtx);
    assertNull(c);
  }
}
