/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import static org.junit.jupiter.api.Assertions.*;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class SSLStorageTest {

  static class DummySSLEngine extends SSLEngine {
    @Override
    public String getPeerHost() {
      return null;
    }

    @Override
    public int getPeerPort() {
      return 0;
    }

    @Override
    public void beginHandshake() {}

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
      return null;
    }

    @Override
    public void closeInbound() {}

    @Override
    public boolean isInboundDone() {
      return false;
    }

    @Override
    public void closeOutbound() {}

    @Override
    public boolean isOutboundDone() {
      return false;
    }

    @Override
    public String[] getSupportedCipherSuites() {
      return new String[0];
    }

    @Override
    public String[] getEnabledCipherSuites() {
      return new String[0];
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {}

    @Override
    public String[] getSupportedProtocols() {
      return new String[0];
    }

    @Override
    public String[] getEnabledProtocols() {
      return new String[0];
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {}

    @Override
    public Runnable getDelegatedTask() {
      return null;
    }

    @Override
    public boolean getEnableSessionCreation() {
      return false;
    }

    @Override
    public boolean getNeedClientAuth() {
      return false;
    }

    @Override
    public boolean getUseClientMode() {
      return false;
    }

    @Override
    public boolean getWantClientAuth() {
      return false;
    }

    @Override
    public void setEnableSessionCreation(boolean b) {}

    @Override
    public void setNeedClientAuth(boolean b) {}

    @Override
    public void setUseClientMode(boolean b) {}

    @Override
    public void setWantClientAuth(boolean b) {}

    @Override
    public javax.net.ssl.SSLSession getHandshakeSession() {
      return null;
    }

    @Override
    public javax.net.ssl.SSLSession getSession() {
      return null;
    }

    @Override
    public SSLEngineResult unwrap(java.nio.ByteBuffer src, java.nio.ByteBuffer dst) {
      return null;
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts, int offset, int length)
        throws SSLException {
      return null;
    }

    @Override
    public SSLEngineResult wrap(java.nio.ByteBuffer src, java.nio.ByteBuffer dst) {
      return null;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int length, ByteBuffer dst)
        throws SSLException {
      return null;
    }
  }

  @AfterEach
  void cleanup() {
    // Clean up thread locals
    SSLStorage.unencrypted.remove();
    SSLStorage.nettyConnection.remove();
  }

  @Test
  void testSessionConnectionMapping() throws Exception {
    SSLEngine engine = new DummySSLEngine();
    Connection conn =
        new Connection(
            InetAddress.getByName("127.0.0.1"), 1234, InetAddress.getByName("1.2.3.4"), 5678);

    assertNull(SSLStorage.getConnectionForSession(engine));
    SSLStorage.setConnectionForSession(engine, conn);
    assertEquals(conn, SSLStorage.getConnectionForSession(engine));
  }

  @Test
  void testBufConnectionMapping() throws Exception {
    String bufKey = "buf123";
    Connection conn =
        new Connection(
            InetAddress.getByName("127.0.0.2"), 4321, InetAddress.getByName("5.6.7.8"), 8765);

    assertNull(SSLStorage.getConnectionForBuf(bufKey));
    SSLStorage.setConnectionForBuf(bufKey, conn);
    assertEquals(conn, SSLStorage.getConnectionForBuf(bufKey));
    assertEquals(bufKey, conn.getBufferKey());
  }

  @Test
  void testActiveConnectionTracking() throws Exception {
    Connection conn =
        new Connection(
            InetAddress.getByName("127.0.0.3"), 1111, InetAddress.getByName("8.8.8.8"), 2222);

    assertTrue(SSLStorage.connectionUntracked(conn));
    SSLStorage.setConnectionForBuf("bufX", conn);
    assertFalse(SSLStorage.connectionUntracked(conn));
    assertEquals(conn, SSLStorage.getActiveConnection(conn));
  }

  @Test
  void testCleanupConnectionBufMapping() throws Exception {
    String bufKey = "bufY";
    Connection conn =
        new Connection(
            InetAddress.getByName("127.0.0.4"), 3333, InetAddress.getByName("9.9.9.9"), 4444);

    SSLStorage.setConnectionForBuf(bufKey, conn);
    assertEquals(conn, SSLStorage.getConnectionForBuf(bufKey));
    SSLStorage.cleanupConnectionBufMapping(conn);
    assertNull(SSLStorage.getConnectionForBuf(bufKey));
    assertNull(SSLStorage.getActiveConnection(conn));
  }

  @Test
  void testBufferMapping() {
    String encrypted = "enc";
    BytesWithLen plain = new BytesWithLen(new byte[] {1, 2, 3}, 3);

    assertNull(SSLStorage.getUnencryptedBuffer(encrypted));
    SSLStorage.setBufferMapping(encrypted, plain);
    assertEquals(plain, SSLStorage.getUnencryptedBuffer(encrypted));
    SSLStorage.removeBufferMapping(encrypted);
    assertNull(SSLStorage.getUnencryptedBuffer(encrypted));
  }
}
