/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations.util;

import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)
public class ByteBufferExtractorBenchmark {

  @Param({"heap", "direct"})
  private String bufferType;

  @Param({"16", "64", "256", "1024"})
  private int bufferSize;

  private ByteBuffer singleBuffer;
  private ByteBuffer[] bufferArray;
  private ByteBuffer[] srcBufferArray;

  @Setup(Level.Trial)
  public void setup() {
    // Setup single buffer
    singleBuffer = allocateBuffer(bufferSize);
    fillBuffer(singleBuffer);

    // Setup buffer array (4 buffers for flattenDstByteBufferArray)
    int arraySize = 4;
    bufferArray = new ByteBuffer[arraySize];
    for (int i = 0; i < arraySize; i++) {
      bufferArray[i] = allocateBuffer(bufferSize / arraySize);
      fillBuffer(bufferArray[i]);
    }

    // Setup source buffer array (4 buffers for flattenSrcByteBufferArray)
    srcBufferArray = new ByteBuffer[arraySize];
    for (int i = 0; i < arraySize; i++) {
      srcBufferArray[i] = allocateBuffer(bufferSize / arraySize);
      fillBuffer(srcBufferArray[i]);
      srcBufferArray[i].flip(); // Prepare for reading
    }
  }

  @TearDown(Level.Invocation)
  public void resetBuffers() {
    // Reset single buffer
    singleBuffer.clear();
    fillBuffer(singleBuffer);

    // Reset buffer arrays
    for (ByteBuffer buf : bufferArray) {
      buf.clear();
      fillBuffer(buf);
    }

    for (ByteBuffer buf : srcBufferArray) {
      buf.clear();
      fillBuffer(buf);
      buf.flip();
    }
  }

  private ByteBuffer allocateBuffer(int size) {
    if ("direct".equals(bufferType)) {
      return ByteBuffer.allocateDirect(size);
    } else {
      return ByteBuffer.allocate(size);
    }
  }

  private void fillBuffer(ByteBuffer buffer) {
    for (int i = 0; i < buffer.capacity(); i++) {
      buffer.put((byte) (i % 256));
    }
  }

  @Benchmark
  public void benchmarkFlattenDstByteBufferArray(Blackhole blackhole) {
    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(bufferArray, bufferSize);
    blackhole.consume(result);
  }

  @Benchmark
  public void benchmarkFlattenSrcByteBufferArray(Blackhole blackhole) {
    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(srcBufferArray);
    blackhole.consume(result);
  }

  @Benchmark
  public void benchmarkSrcBufferArray(Blackhole blackhole) {
    singleBuffer.flip(); // Prepare for reading
    ByteBuffer result = ByteBufferExtractor.fromFreshBuffer(singleBuffer, bufferSize);
    blackhole.consume(result);
  }

  @Benchmark
  public void benchmarkBufferKey(Blackhole blackhole) {
    String result = ByteBufferExtractor.keyFromUsedBuffer(singleBuffer);
    blackhole.consume(result);
  }

  @Benchmark
  public void benchmarkSrcBufferKey(Blackhole blackhole) {
    singleBuffer.flip(); // Prepare for reading
    String result = ByteBufferExtractor.keyFromFreshBuffer(singleBuffer);
    blackhole.consume(result);
  }

  // Additional benchmarks for edge cases

  @Benchmark
  public void benchmarkFlattenDstByteBufferArrayNull(Blackhole blackhole) {
    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(null, bufferSize);
    blackhole.consume(result);
  }

  @Benchmark
  public void benchmarkFlattenSrcByteBufferArrayNull(Blackhole blackhole) {
    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(null);
    blackhole.consume(result);
  }

  @Benchmark
  public void benchmarkSrcBufferArrayNull(Blackhole blackhole) {
    ByteBuffer result = ByteBufferExtractor.fromFreshBuffer(null, bufferSize);
    blackhole.consume(result);
  }

  // Benchmarks with different array sizes
  @State(Scope.Benchmark)
  public static class LargeArrayState {
    @Param({"heap", "direct"})
    private String bufferType;

    @Param({"2", "8", "16"})
    private int arrayLength;

    private ByteBuffer[] largeArray;

    @Setup(Level.Trial)
    public void setup() {
      largeArray = new ByteBuffer[arrayLength];
      for (int i = 0; i < arrayLength; i++) {
        if ("direct".equals(bufferType)) {
          largeArray[i] = ByteBuffer.allocateDirect(128);
        } else {
          largeArray[i] = ByteBuffer.allocate(128);
        }
        for (int j = 0; j < largeArray[i].capacity(); j++) {
          largeArray[i].put((byte) (j % 256));
        }
      }
    }

    @TearDown(Level.Invocation)
    public void resetBuffers() {
      for (ByteBuffer buf : largeArray) {
        buf.clear();
        for (int j = 0; j < buf.capacity(); j++) {
          buf.put((byte) (j % 256));
        }
      }
    }
  }

  @Benchmark
  public void benchmarkFlattenDstByteBufferArrayLarge(LargeArrayState state, Blackhole blackhole) {
    ByteBuffer result = ByteBufferExtractor.flattenUsedByteBufferArray(state.largeArray, 1024);
    blackhole.consume(result);
  }

  @Benchmark
  public void benchmarkFlattenSrcByteBufferArrayLarge(LargeArrayState state, Blackhole blackhole) {
    for (ByteBuffer buf : state.largeArray) {
      buf.flip();
    }
    ByteBuffer result = ByteBufferExtractor.flattenFreshByteBufferArray(state.largeArray);
    blackhole.consume(result);
  }

  // Benchmarks for key generation with different sizes
  @State(Scope.Benchmark)
  public static class KeyGenerationState {
    @Param({"heap", "direct"})
    private String bufferType;

    @Param({"32", "64", "128", "256"})
    private int keyBufferSize;

    private ByteBuffer keyBuffer;

    @Setup(Level.Trial)
    public void setup() {
      if ("direct".equals(bufferType)) {
        keyBuffer = ByteBuffer.allocateDirect(keyBufferSize);
      } else {
        keyBuffer = ByteBuffer.allocate(keyBufferSize);
      }
      for (int i = 0; i < keyBufferSize; i++) {
        keyBuffer.put((byte) (i % 256));
      }
    }

    @TearDown(Level.Invocation)
    public void resetBuffer() {
      keyBuffer.clear();
      for (int i = 0; i < keyBufferSize; i++) {
        keyBuffer.put((byte) (i % 256));
      }
    }
  }

  @Benchmark
  public void benchmarkBufferKeyVaryingSize(KeyGenerationState state, Blackhole blackhole) {
    String result = ByteBufferExtractor.keyFromUsedBuffer(state.keyBuffer);
    blackhole.consume(result);
  }

  @Benchmark
  public void benchmarkSrcBufferKeyVaryingSize(KeyGenerationState state, Blackhole blackhole) {
    state.keyBuffer.flip();
    String result = ByteBufferExtractor.keyFromFreshBuffer(state.keyBuffer);
    blackhole.consume(result);
  }
}
