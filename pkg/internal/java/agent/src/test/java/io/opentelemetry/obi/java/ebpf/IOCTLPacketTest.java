/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import io.opentelemetry.obi.java.instrumentations.data.Connection;
import org.junit.jupiter.api.Test;

// Memory Layout of Pointer p (after pos.write(new byte[] {42}))
// ═══════════════════════════════════════════════════════════════

// Offset    Size    Value    Description
// ───────────────────────────────────────────────────────────────
//   0        1B      0x01     OperationType.SEND.code
//                           ┌─────────────────────────────┐
//   1       36B      ...    |ConnectionInfo (36 bytes)    │ packetPrefixSize
//                           │ (socket connection data)    │ = 1 + 36 + 4
//                           └─────────────────────────────┘
//  37        4B      0x01     Buffer length (int = 1)
//                           ┌─────────────────────────────┐
//  41        1B      0x2A   |Data byte: 42                │ Actual payload
//                           └─────────────────────────────┘

// Total size: 1 + 36 + 4 + 1 = 42 bytes

// Test assertions:
// ───────────────────────────────────────────────────────────────
// p.getByte(0)           → 1    (OperationType.SEND)
// p.getInt(1 + 36)       → 1    (Buffer length at offset 37)
// p.getByte(1 + 36 + 4)  → 42   (Data byte at offset 41)

class IOCTLPacketTest {

  @Test
  void testWritePacketPrefixWithNullSocket() {
    Pointer mem = new Memory(64);
    int off = 0;
    OperationType type = OperationType.SEND;
    int bufLen = 10;

    int newOff = IOCTLPacket.writePacketPrefix(mem, off, type, (java.net.Socket) null, bufLen);

    assertEquals(IOCTLPacket.packetPrefixSize, newOff);
    assertEquals(type.code, mem.getByte(0));
    assertEquals(bufLen, mem.getInt(1 + 36));
  }

  @Test
  void testWritePacketPrefixWithNullConnection() {
    Pointer mem = new Memory(64);
    int off = 0;
    OperationType type = OperationType.RECEIVE;
    int bufLen = 20;

    int newOff = IOCTLPacket.writePacketPrefix(mem, off, type, (Connection) null, bufLen);

    assertEquals(IOCTLPacket.packetPrefixSize, newOff);
    assertEquals(type.code, mem.getByte(0));
    assertEquals(bufLen, mem.getInt(1 + 36));
  }

  @Test
  void testWritePacketPrefixWithConnection() {
    Pointer mem = new Memory(64);
    int off = 0;
    OperationType type = OperationType.RECEIVE;
    int bufLen = 20;

    int newOff = IOCTLPacket.writePacketPrefix(mem, off, type, (Connection) null, bufLen);

    assertEquals(IOCTLPacket.packetPrefixSize, newOff);
    assertEquals(type.code, mem.getByte(0));
    assertEquals(bufLen, mem.getInt(1 + 36));
  }

  @Test
  void testWritePacketBuffer() {
    Pointer mem = new Memory(32);
    int off = 5;
    byte[] buf = {1, 2, 3, 4};

    int newOff = IOCTLPacket.writePacketBuffer(mem, off, buf);

    assertEquals(off + buf.length, newOff);
    for (int i = 0; i < buf.length; i++) {
      assertEquals(buf[i], mem.getByte(off + i));
    }
  }
}
