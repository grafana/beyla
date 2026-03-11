# OpenTelemetry eBPF Instrumentation (OBI) Java Agent

A Java instrumentation agent for Java TLS observability using eBPF integration.
This agent intercepts sync and async TLS network I/O operations in Java applications and
communicates with eBPF programs for distributed tracing and monitoring.

## 🚀 Features

- **Dynamic attach** - Attach to running JVMs without code changes
- **Socket-level tracing** - Instruments `javax.net.ssl.SSLSocket` and `java.nio.channels.SocketChannel` operations
- **SSL/TLS support** - Intercepts `javax.net.ssl.SSLEngine` for encrypted traffic
- **Netty support** - Instruments Netty channels for reactive applications

## 📋 Basic concepts

There are two main ways Java will create TLS traffic:

1. Synchronous by using `SSLSocket`.
2. Asynchronous by using `SSLEngine` to encrypt/decrypt and some mechanism to send the data,
which is typically done though socket channels. We support the native JDK `SocketChannel`
implementations and `Netty's` socket channels.

With this bytecode instrumentation, we intercept the TLS traffic and we ship the data to
OBI along with the connection information. We communicate with OBI via making a native C
library call to `ioctl`, which in turn makes a syscall. OBI attaches a kprobe to
`do_vfs_ioctl` and intercepts the data sent from the Java agent.

OBI cares about two main pieces of information to be able to correctly report and nest the
TLS Java calls:

1. The unencrypted TLS buffers.
2. The connection information.

When dealing with synchronous TLS traffic (e.g. SSLSocket), the encryption and socket
communication is all done on the same thread and by the same Java class. In this case,
we simply inject a wrapper around the `SSLSocket` and capture the required buffers and
connection information.

Asynchronous traffic is more complex. Typically, the encryption, decryption and the
communication are not done on the same thread, and definitely not done by the same class.
In order to match the connection information to the unencrypted buffers, the agent injects
code to do the following:

1. At the time of encryption/decryption (via SSLEngine) we create keys from the
encrypted text (which should be random with enough length) and map that to the
unencrypted buffer.
2. At the time of socket communication we have the connection information, and the
encrypted buffer. We consult the map of decrypted buffers, based on the encrypted
buffer keys and join that with the connection information. Once we have both parts
we make the same C library call to `ioctl`.

## 📋 Table of Contents

- [Architecture](#architecture)
- [Building](#building)
- [Usage](#usage)
- [Instrumented Components](#instrumented-components)
- [Benchmarking](#benchmarking)
- [Testing](#testing)

## 🏗️ Architecture

The project consists of two main modules:

### 1. Agent Module (`agent/`)

The core instrumentation logic using ByteBuddy for bytecode manipulation:

- **Instrumentations**: Socket, SocketChannel, SSLEngine, Netty
- **eBPF Communication**: Via JNA and `ioctl` syscalls for minimal kernel impact
- **Data Structures**: Connection tracking, SSL session management
- **Utilities**: Optimized ByteBuffer extraction and manipulation

### 2. Loader Module (`loader/`)

A lightweight loader that:

- Extracts the agent JAR from resources
- Loads the agent using a separate classloader to avoid conflicts with the
  target application
- Ensures JNA is available in the bootstrap classloader
- Handles agent attachment (both premain and agentmain)

```
┌───────────────────┐
│  Java App         │
│                   │
│  ┌───────────┐    │
│  │ OBI Agent │◄───┼─── Attaches via -javaagent
│  └─────┬─────┘    │
│        │          │
│  ┌─────▼──────┐   │
│  │Instrumented│   │
│  │   Code     │   │
│  └─────┬──────┘   │
└────────┼──────────┘
         │ ioctl
         ▼
   ┌──────────┐
   │   OBI    │
   └──────────┘
```

### 3. Communicating with the eBPF side

The Java code prepares a packet which is supplied to the `ioctl` C library call. The
packet will contain information about the connection as well as the decrypted payload.

The `ioctl` call uses custom constant (`0x0b10b1`) for the `id` parameter. We look for
this magic number on the eBPF side to ensure the `ioctl` call is for our purpose.

The payload we send to the eBPF side has this format:

```
Memory Layout of Pointer p (after pos.write(new byte[] {42}))
═══════════════════════════════════════════════════════════════

Offset    Size    Value    Description
───────────────────────────────────────────────────────────────
  0        1B      0x01     OperationType.SEND.code
                          ┌─────────────────────────────┐
  1       36B      ...    |ConnectionInfo (36 bytes)    │ packetPrefixSize
                          │ (socket connection data)    │ = 1 + 36 + 4
                          └─────────────────────────────┘
 37        4B      0x01     Buffer length (int = 1)
                          ┌─────────────────────────────┐
 41        1B      0x2A   |Data byte: 42                │ Actual payload
                          └─────────────────────────────┘

Total size: 1 + 36 + 4 + 1 = 42 bytes

Test assertions:
───────────────────────────────────────────────────────────────
p.getByte(0)           → 1    (OperationType.SEND)
p.getInt(1 + 36)       → 1    (Buffer length at offset 37)
p.getByte(1 + 36 + 4)  → 42   (Data byte at offset 41)
```

## 🔨 Building

### Prerequisites

- Docker and GNU Make (recommended; no local Gradle install required), or
- Local Gradle 9.x and JDK 17+ (for running Gradle locally)

Note: the Java agent bytecode target is Java 8, but Gradle itself requires JDK 17+ to run.

### Build Commands

Run these commands from the repository root.

#### Option A: Local Gradle

```bash
# Build Java agent and copy it to pkg/internal/java/embedded/obi-java-agent.jar
make java-build

# Run Java tests
make java-test

# Check formatting
make java-spotless-check

# Apply formatting
make java-spotless-apply
```

You can also run Gradle directly from `pkg/internal/java`:

```bash
# Build all modules and distribution
gradle build

# Build only the agent
gradle :agent:build

# Build only the loader
gradle :loader:build

# Fix code formatting
gradle spotlessApply

```

#### Option B: Docker-only (no local Gradle)

```bash
# Build Java agent artifact using javaagent.Dockerfile and export it to:
# pkg/internal/java/embedded/obi-java-agent.jar
make java-docker-build
```

The final agent JAR will be located at:

```
build/obi-java-agent.jar
```

## 📦 Usage

### Attach at Startup

```bash
java -javaagent:/path/to/obi-java-agent.jar -jar your-application.jar
```

### Attach to Running JVM

Using [jattach](https://github.com/jattach/jattach).

```bash
jattach <PID of Java program> load instrument false "/path/to/obi-java-agent.jar"
```

### Enable Debug Mode (stdout)

```bash
java -javaagent:/path/to/obi-java-agent.jar=debug=true \
     -jar your-application.jar
```

or for dynamic attach

```bash
jattach <PID of Java program> load instrument false "/path/to/obi-java-agent.jar=debug=true"
```

### Enable Debug for ByteBuddy instrumentation (stdout)

```bash
java -javaagent:/path/to/obi-java-agent.jar=debugBB=true \
     -jar your-application.jar
```

or for dynamic attach

```bash
jattach <PID of Java program> load instrument false "/path/to/obi-java-agent.jar=debugBB=true"
```

## 🔍 Instrumented Components

### 1. **javax.net.ssl.SSLSocket** for synchronous TLS

- `getInputStream()` - Returns wrapped InputStream
- `getOutputStream()` - Returns wrapped OutputStream
- Tracks connection metadata (local/remote address, ports)

### 2. **java.nio.channels.SocketChannel** for asynchronous TLS

- `read(ByteBuffer)` - Single buffer reads
- `read(ByteBuffer[])` - Scatter reads
- `write(ByteBuffer)` - Single buffer writes
- `write(ByteBuffer[])` - Gather writes
- `shutdownInput` - clean-up
- `shutdownOutput` - clean-up
- `kill` - clean-up
- `tryClose` - clean-up

### 3. **javax.net.ssl.SSLEngine** for asynchronous TLS

- `wrap(ByteBuffer)` - Encrypting outbound data
- `wrap(ByteBuffer[])` - Encrypting outbound data
- `unwrap(ByteBuffer)` - Decrypting inbound data
- `unwrap(ByteBuffer[])` - Decrypting inbound data
- SSL session to connection mapping

### 4. **io.netty.handler.ssl.SslHandler** for Netty channels (which don't use JDK SocketChannel)

- `wrap()` - Extracts connection info
- `unwrap()` - Extracts connection info

## 💻 Development

### Key Technologies

- **ByteBuddy** - Bytecode manipulation and agent building
- **JNA (Java Native Access)** - Native library calls (ioctl)
- **Caffeine** - High-performance LRU for keeping track of existing connections

### Adding New Instrumentations

1. Create a new class in `instrumentations/`
2. Implement ByteBuddy `AgentBuilder.Transformer`
3. Register in `Agent.java`
4. Add to re-transform list in `Agent.java` for dynamic attach
5. Add tests in `src/test/java/`

## 📊 Benchmarking

### Running Benchmarks

```bash
# Run all benchmarks
gradle :agent:jmh

# Run specific benchmark
gradle :agent:jmh -Pjmh.includes=benchmarkFlattenDstByteBufferArray

# Run with GC profiling
gradle :agent:jmh -Pjmh.profilers=gc

# Run with memory allocation profiling
gradle :agent:jmh -Pjmh.profilers=gc,stack
```

### Benchmark Results

See `agent/src/jmh/java/io/opentelemetry/obi/java/instrumentations/util/BENCHMARK_README.md` for detailed benchmarking documentation.

Example results (ns/op, lower is better):

```
Benchmark                              (bufferType)  (bufferSize)   Score
flattenDstByteBufferArray                    heap           64    245.3
flattenDstByteBufferArray                  direct           64    523.1
```

## 🧪 Testing

### Unit Tests

```bash
# Run all tests
gradle test

# Run tests for specific module
gradle :agent:test

# Run specific test class
gradle :agent:test --tests ByteBufferExtractorTest
```

## 📝 License

Apache 2.0 License
