/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.data;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import javax.net.ssl.SSLEngine;

public class SSLStorage {
  public static Method bootExtractMethod = null;
  public static Field bootNettyConnectionField = null;

  public static boolean debugOn = false;

  public static Field bootDebugOn = null;

  private static final int MAX_CONCURRENT = 5_000;
  private static final Cache<SSLEngine, Connection> sslConnections =
      Caffeine.newBuilder().maximumSize(MAX_CONCURRENT).build();
  private static final Cache<String, BytesWithLen> bufToBuf =
      Caffeine.newBuilder().maximumSize(MAX_CONCURRENT).build();

  private static final Cache<String, Connection> bufConn =
      Caffeine.newBuilder().maximumSize(MAX_CONCURRENT).build();

  private static final Cache<Connection, Connection> activeConnections =
      Caffeine.newBuilder().maximumSize(MAX_CONCURRENT).build();

  private static final Cache<Integer, Long> tasks =
      Caffeine.newBuilder().maximumSize(MAX_CONCURRENT).build();

  public static final ThreadLocal<BytesWithLen> unencrypted = new ThreadLocal<>();

  public static final ThreadLocal<Object> nettyConnection = new ThreadLocal<>();

  public static Connection getConnectionForSession(SSLEngine session) {
    return sslConnections.getIfPresent(session);
  }

  public static void setConnectionForSession(SSLEngine session, Connection c) {
    sslConnections.put(session, c);
  }

  public static Connection getConnectionForBuf(String buf) {
    return bufConn.getIfPresent(buf);
  }

  public static boolean connectionUntracked(Connection c) {
    return activeConnections.getIfPresent(c) == null;
  }

  public static Connection getActiveConnection(Connection c) {
    return activeConnections.getIfPresent(c);
  }

  public static void setConnectionForBuf(String buf, Connection c) {
    c.setBufferKey(buf);
    bufConn.put(buf, c);
    activeConnections.put(c, c);
  }

  public static void cleanupConnectionBufMapping(Connection c) {
    bufConn.invalidate(c.getBufferKey());
    activeConnections.invalidate(c);
  }

  public static void setBufferMapping(String encrypted, BytesWithLen plain) {
    bufToBuf.put(encrypted, plain);
  }

  public static BytesWithLen getUnencryptedBuffer(String encrypted) {
    return bufToBuf.getIfPresent(encrypted);
  }

  public static void removeBufferMapping(String encrypted) {
    bufToBuf.invalidate(encrypted);
  }

  // These boot finder methods are here to help us find the version of the methods/classes that are
  // loaded
  // on the boot class loader. Since we use multiple class loaders, we need to be able to find a
  // specific version
  // of the class.
  public static Method getBootExtractMethod() {
    if (bootExtractMethod == null) {
      try {
        Class<?> extractorClass =
            Class.forName(
                "io.opentelemetry.obi.java.instrumentations.util.NettyChannelExtractor",
                true,
                null); // null for bootstrap loader
        bootExtractMethod =
            extractorClass.getMethod("extractConnectionFromChannelHandlerContext", Object.class);
      } catch (Exception x) {
        System.err.println("[SSLStorage] Failed to get boot extract method " + x);
      }
    }
    return bootExtractMethod;
  }

  public static Field getBootNettyConnectionField() {
    if (bootNettyConnectionField == null) {
      try {
        Class<?> sslStorageClass =
            Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
        bootNettyConnectionField = sslStorageClass.getDeclaredField("nettyConnection");
      } catch (Exception x) {
        System.err.println("[SSLStorage] Failed to get boot netty connection field " + x);
      }
    }

    return bootNettyConnectionField;
  }

  public static Field getBootDebugOn() {
    if (bootDebugOn == null) {
      try {
        Class<?> sslStorageClass =
            Class.forName("io.opentelemetry.obi.java.instrumentations.data.SSLStorage", true, null);
        bootDebugOn = sslStorageClass.getDeclaredField("debugOn");
      } catch (Exception x) {
        System.err.println("[SSLStorage] Failed to get boot debug on " + x);
      }
    }

    return bootDebugOn;
  }

  public static Object bootDebugOn() {
    try {
      Field debugOn = getBootDebugOn();
      if (debugOn == null) {
        return false;
      }
      return debugOn.get(null);
    } catch (Exception x) {
      System.err.println("[SSLStorage] Failed to get boot debug on " + x);
    }

    return false;
  }

  public static void trackTask(long threadId, Object task) {
    if (task == null) {
      return;
    }
    tasks.put(System.identityHashCode(task), threadId);
  }

  public static void untrackTask(Object task) {
    if (task == null) {
      return;
    }
    tasks.invalidate(System.identityHashCode(task));
  }

  public static Long parentThreadId(Object task) {
    if (task == null) {
      return null;
    }

    return tasks.getIfPresent(System.identityHashCode(task));
  }
}
