/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import com.sun.jna.Pointer;
import io.opentelemetry.obi.java.instrumentations.data.Connection;
import java.net.InetAddress;
import java.net.Socket;

public class ConnectionInfo {
  private static byte[] empty = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  private static void writeInetAddress(Pointer mem, int off, InetAddress addr) {
    if (addr == null) {
      mem.write(off, empty, 0, empty.length);
      return;
    }
    byte[] data = addr.getAddress();
    if (data.length == 16) { // IPv6
      mem.write(off, data, 0, data.length);
    } else if (data.length == 4) { // IPv4
      byte[] ipv6data = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xff, (byte) 0xff, 0, 0, 0, 0};
      System.arraycopy(data, 0, ipv6data, 12, 4);
      mem.write(off, ipv6data, 0, ipv6data.length);
    } else {
      throw new RuntimeException("unknown InetAddress format");
    }
  }

  public static int writeRecvConnectionInfo(Pointer mem, int off, Socket sock) {
    Connection c =
        new Connection(
            sock.getLocalAddress(), sock.getLocalPort(), sock.getInetAddress(), sock.getPort());
    return writeRecvConnectionInfo(mem, off, c);
  }

  public static int writeRecvConnectionInfo(Pointer mem, int off, Connection conn) {
    InetAddress remoteAddress = conn.getRemoteAddress();
    writeInetAddress(mem, off, remoteAddress);
    off += 16;
    InetAddress localAddress = conn.getLocalAddress();
    writeInetAddress(mem, off, localAddress);
    off += 16;
    int remotePort = conn.getRemotePort();
    mem.setShort(off, (short) remotePort);
    off += 2;
    int localPort = conn.getLocalPort();
    mem.setShort(off, (short) localPort);
    off += 2;

    return off;
  }

  public static int writeSendConnectionInfo(Pointer mem, int off, Socket sock) {
    Connection c =
        new Connection(
            sock.getLocalAddress(), sock.getLocalPort(), sock.getInetAddress(), sock.getPort());
    return writeSendConnectionInfo(mem, off, c);
  }

  public static int writeSendConnectionInfo(Pointer mem, int off, Connection conn) {
    InetAddress localAddress = conn.getLocalAddress();
    writeInetAddress(mem, off, localAddress);
    off += 16;
    InetAddress remoteAddress = conn.getRemoteAddress();
    writeInetAddress(mem, off, remoteAddress);
    off += 16;
    int localPort = conn.getLocalPort();
    mem.setShort(off, (short) localPort);
    off += 2;
    int remotePort = conn.getRemotePort();
    mem.setShort(off, (short) remotePort);
    off += 2;

    return off;
  }

  public static int writeEmptyConnectionInfo(Pointer mem, int off) {
    byte[] empty = new byte[36];
    mem.write(off, empty, 0, empty.length);
    return off + 36;
  }
}
