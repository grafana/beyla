/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import java.net.InetAddress;
import java.util.Objects;

public class Connection {
  private final InetAddress localAddress;
  private final int localPort;
  private final InetAddress remoteAddress;
  private final int remotePort;

  private String bufferKey = null;

  public Connection(
      InetAddress localAddress, int localPort, InetAddress remoteAddress, int remotePort) {
    this.localAddress = localAddress;
    this.localPort = localPort;
    this.remoteAddress = remoteAddress;
    this.remotePort = remotePort;
  }

  public InetAddress getLocalAddress() {
    return localAddress;
  }

  public int getLocalPort() {
    return localPort;
  }

  public InetAddress getRemoteAddress() {
    return remoteAddress;
  }

  public int getRemotePort() {
    return remotePort;
  }

  @Override
  public boolean equals(Object o) {
    if (o == null || getClass() != o.getClass()) return false;
    Connection that = (Connection) o;
    return localPort == that.localPort
        && remotePort == that.remotePort
        && Objects.equals(localAddress, that.localAddress)
        && Objects.equals(remoteAddress, that.remoteAddress);
  }

  @Override
  public int hashCode() {
    return Objects.hash(localAddress, localPort, remoteAddress, remotePort);
  }

  // Buffer key is not part of the hashcode/equals, we want to compare in maps without it.
  public String getBufferKey() {
    return bufferKey;
  }

  public void setBufferKey(String bufferKey) {
    this.bufferKey = bufferKey;
  }
}
