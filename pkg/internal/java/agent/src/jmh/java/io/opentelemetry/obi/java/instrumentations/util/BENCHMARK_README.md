# ByteBufferExtractor Benchmarks

This directory contains JMH (Java Microbenchmark Harness) benchmarks for the `ByteBufferExtractor` class.

## Running the Benchmarks

### Prerequisites

- JDK 8 or higher
- Gradle

### Run all benchmarks

From the root directory:

```bash
./gradlew :agent:jmh
```

### Run specific benchmark method

```bash
./gradlew :agent:jmh -Pjmh.includes=benchmarkFlattenDstByteBufferArray
```

## Benchmark Parameters

The benchmarks test the following scenarios:

### Buffer Types

- **heap**: Standard heap-allocated ByteBuffers (`ByteBuffer.allocate()`)
- **direct**: Direct (off-heap) ByteBuffers (`ByteBuffer.allocateDirect()`)

### Buffer Sizes

- 16 bytes
- 64 bytes
- 256 bytes
- 1024 bytes

### Array Lengths (for array-based benchmarks)

- 2 buffers
- 8 buffers
- 16 buffers

## Benchmarked Methods

1. **flattenDstByteBufferArray**: Flattens an array of destination ByteBuffers
2. **flattenSrcByteBufferArray**: Flattens an array of source ByteBuffers
3. **srcBufferArray**: Creates a buffer from a single source ByteBuffer
4. **bufferKey**: Generates a string key from a ByteBuffer (flip-based)
5. **srcBufferKey**: Generates a string key from a ByteBuffer (remaining-based)

## Interpreting Results

JMH will output results showing:

- **Score**: Average time per operation (in nanoseconds by default)
- **Error**: Margin of error
- **Units**: Time unit (ns/op = nanoseconds per operation)

Lower scores indicate better performance.

## Example Output

```
Benchmark                                                      (bufferSize)  (bufferType)  Mode  Cnt    Score    Error  Units
ByteBufferExtractorBenchmark.benchmarkFlattenDstByteBufferArray         64          heap  avgt    5  123.456 ± 12.345  ns/op
ByteBufferExtractorBenchmark.benchmarkFlattenDstByteBufferArray         64        direct  avgt    5  234.567 ± 23.456  ns/op
```

## Memory Profiling Commands

### GC Profiler (shows garbage collection stats)

```
./gradlew :agent:jmh -Pjmh.profilers=gc
```

### Memory Allocation Profiler

```
./gradlew :agent:jmh -Pjmh.profilers=gc,stack
```

### Heap Allocation Profiler (detailed allocation tracking)

```
./gradlew :agent:jmh -Pjmh.profilers=gc,hs_gc
```

### Multiple Profilers (comprehensive memory analysis)

```
./gradlew :agent:jmh -Pjmh.profilers=gc,stack,hs_gc
```

### Specific benchmark with profiler

```
./gradlew :agent:jmh -Pjmh.includes=benchmarkFlattenDstByteBufferArray -Pjmh.profilers=gc
```

Available Memory-Related Profilers:

- gc - GC profiling (heap allocations, GC time, counts)
- hs_gc - HotSpot GC profiling (more detailed GC info)
- stack - Stack profiling (shows where time is spent)
- pauses - Detects JVM pauses
- safepoints - Shows safepoint information
