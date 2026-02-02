/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import com.sun.jna.Pointer;
import io.opentelemetry.obi.java.instrumentations.data.Connection;
import java.net.Socket;

public class IOCTLPacket {
  public static int packetPrefixSize = 1 + 36 + 4; // operation + connection_info_t + buf_len

  public static int writePacketPrefix(
      Pointer mem, int off, OperationType type, Socket socket, int bufLen) {
    mem.setByte(off, type.code);
    off++;
    if (socket == null) {
      off = ConnectionInfo.writeEmptyConnectionInfo(mem, off);
    } else {
      if (type == OperationType.SEND) {
        off = ConnectionInfo.writeSendConnectionInfo(mem, off, socket);
      } else {
        off = ConnectionInfo.writeRecvConnectionInfo(mem, off, socket);
      }
    }
    mem.setInt(off, bufLen);
    off += 4;

    return off;
  }

  public static int writePacketPrefix(
      Pointer mem, int off, OperationType type, Connection conn, int bufLen) {
    mem.setByte(off, type.code);
    off++;
    if (conn == null) {
      off = ConnectionInfo.writeEmptyConnectionInfo(mem, off);
    } else {
      if (type == OperationType.SEND) {
        off = ConnectionInfo.writeSendConnectionInfo(mem, off, conn);
      } else {
        off = ConnectionInfo.writeRecvConnectionInfo(mem, off, conn);
      }
    }
    mem.setInt(off, bufLen);
    off += 4;

    return off;
  }

  public static int writePacketBuffer(Pointer mem, int wOff, byte[] buf, int index, int len) {
    mem.write(wOff, buf, index, len);
    wOff += len;

    return wOff;
  }

  public static int writePacketBuffer(Pointer mem, int off, byte[] buf) {
    return writePacketBuffer(mem, off, buf, 0, buf.length);
  }

  public static int writePacket(Pointer mem, int off, OperationType type, long parentId) {
    mem.setByte(off, type.code);
    off++;
    off = ThreadInfo.writeThreadContext(mem, off, parentId);
    return off;
  }
}
