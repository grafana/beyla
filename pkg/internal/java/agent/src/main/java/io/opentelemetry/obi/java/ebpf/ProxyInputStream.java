/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import io.opentelemetry.obi.java.Agent;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

public class ProxyInputStream extends InputStream {
  private final InputStream delegate;
  private final Socket socket;

  static Agent.CLibrary instance = Agent.CLibrary.INSTANCE;

  public ProxyInputStream(InputStream delegate, Socket socket) {
    this.delegate = delegate;
    this.socket = socket;
  }

  @Override
  public int read() throws IOException {
    return delegate.read();
  }

  @Override
  public int read(byte[] b) throws IOException {
    int len = delegate.read(b);
    if (len > 0) {
      Pointer p = new Memory(IOCTLPacket.packetPrefixSize + b.length);
      int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.RECEIVE, socket, b.length);
      IOCTLPacket.writePacketBuffer(p, wOff, b);
      instance.ioctl(0, Agent.IOCTL_CMD, Pointer.nativeValue(p));
    }
    return len;
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    int bytesRead = delegate.read(b, off, len);
    if (bytesRead > 0) {
      Pointer p = new Memory(IOCTLPacket.packetPrefixSize + bytesRead);
      int wOff = IOCTLPacket.writePacketPrefix(p, 0, OperationType.RECEIVE, socket, bytesRead);
      IOCTLPacket.writePacketBuffer(p, wOff, b, off, bytesRead);
      instance.ioctl(0, Agent.IOCTL_CMD, Pointer.nativeValue(p));
    }
    return bytesRead;
  }

  @Override
  public void close() throws IOException {
    delegate.close();
  }
}
