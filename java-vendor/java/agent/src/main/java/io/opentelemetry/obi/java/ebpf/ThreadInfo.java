/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

import com.sun.jna.Pointer;

public class ThreadInfo {
  public static int writeThreadContext(Pointer mem, int off, long parentId) {
    mem.setLong(off, parentId);
    off += Long.BYTES;
    return off;
  }
}
