/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.ebpf;

public enum OperationType {
  SEND((byte) 1),
  RECEIVE((byte) 2),
  THREAD((byte) 3);

  public final byte code;

  OperationType(byte code) {
    this.code = code;
  }
}
