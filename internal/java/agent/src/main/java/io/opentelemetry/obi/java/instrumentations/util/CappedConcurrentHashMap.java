/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.util;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReferenceArray;

// This is an LRU map approximation with a ring buffer. It doesn't have
// strong LRU guarantees and it can evict newer entries when duplicates
// are stored in the map. For the purpose of the agent this is sufficient
// since we clean up the data from the maps and we only need a approximate
// LRU capped size concurrent map. Proper LRU requires locking and can
// degrade the Java application concurrency.
public class CappedConcurrentHashMap<K, V> {
  private final ConcurrentHashMap<K, V> map = new ConcurrentHashMap<>();
  private final AtomicReferenceArray<K> ring;
  private final AtomicLong index = new AtomicLong();

  public CappedConcurrentHashMap(int capacity) {
    if (capacity <= 0) {
      throw new IllegalArgumentException("capacity must be > 0");
    }
    this.ring = new AtomicReferenceArray<>(capacity);
  }

  // Not using the JDK Math implementation because it's
  // not available in JDK 8.
  static long floorMod(long x, long y) {
    final long r = x % y;
    // if the signs are different and modulo not zero, adjust result
    if ((x ^ y) < 0 && r != 0) {
      return r + y;
    }
    return r;
  }

  public V put(K key, V value) {
    if (key == null || value == null) {
      return null;
    }

    V prev = map.put(key, value);

    // We are adding a new key, check for overflow and remove an
    // element
    if (prev == null) {
      // This can overflow, but that's OK, the modulo still works with
      // negative numbers because our floorMod implementation uses the
      // sign of the divisor (ring.length())
      long i = index.getAndIncrement();
      int slot = (int) floorMod(i, ring.length());

      K oldKey = ring.getAndSet(slot, key);
      if (oldKey != null && !oldKey.equals(key)) {
        map.remove(oldKey);
      }
    }

    return prev;
  }

  // This is simple enough, and it's the source of the poor LRU properties of
  // this implementation. The ring buffer is not walked and cleared so duplicates
  // may accidentally evict newer entries. For our purpose it works, but it can be
  // improved in the future if needed with adding a version number in the key.
  public V remove(K key) {
    return map.remove(key);
  }

  public V get(K key) {
    return map.get(key);
  }

  int size() {
    return map.size();
  }

  boolean containsKey(K key) {
    return map.containsKey(key);
  }
}
