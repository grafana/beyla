# Build JNI native library using Go image (has gcc, no apt install needed)
FROM golang:1.26.3@sha256:313faae491b410a35402c05d35e7518ae99103d957308e940e1ae2cfa0aac29b AS jni-builder
ARG BUILDARCH=amd64
COPY --from=gradle:9.5.0-jdk21-noble@sha256:41cd88d5934d5880ea7e3ebd53d711155e7e1c989390f0f9fa3dfd7d6b742a28 /opt/java/openjdk/include /opt/java/include
WORKDIR /build
COPY .obi-src/pkg/internal/java/agent/src/main/c/ src/main/c/
COPY .obi-src/pkg/internal/java/agent/Makefile.jni Makefile.jni

# Install the cross compile toolchain
RUN apt update
RUN case "$BUILDARCH" in \
      amd64) CROSS_CC_PKG=gcc-aarch64-linux-gnu ;; \
      arm64) CROSS_CC_PKG=gcc-x86-64-linux-gnu ;; \
      *)     CC=gcc ;; \
    esac && \
    apt-get install $CROSS_CC_PKG -y

# Own architecture
RUN case "$BUILDARCH" in \
      amd64) SLUG=linux-amd64 ;; \
      arm64) SLUG=linux-aarch64 ;; \
      *)     CC=gcc ;; \
    esac && \
    make -f Makefile.jni CC=gcc JAVA_HOME=/opt/java JNI_HEADERS_DIR=src/main/c BUILD_DIR=build/jni/$SLUG TARGET_DIR=target/classes/native/$SLUG

# Cross-compile the other
RUN case "$BUILDARCH" in \
      amd64) CC=aarch64-linux-gnu-gcc \
             SLUG=linux-aarch64 ;; \
      arm64) CC=x86_64-linux-gnu-gcc \
             SLUG=linux-amd64 ;; \
      *)     CC=gcc ;; \
    esac && \
    make -f Makefile.jni CC=$CC JAVA_HOME=/opt/java JNI_HEADERS_DIR=src/main/c BUILD_DIR=build/jni/$SLUG TARGET_DIR=target/classes/native/$SLUG

FROM gradle:9.5.0-jdk21-noble@sha256:41cd88d5934d5880ea7e3ebd53d711155e7e1c989390f0f9fa3dfd7d6b742a28 AS builder

WORKDIR /build

# Copy build files
COPY .obi-src/pkg/internal/java .
# Pre-built native libraries from jni-builder stage
COPY --from=jni-builder /build/target/classes/native/linux-amd64/libobijni.so agent/target/classes/native/linux-amd64/libobijni.so
COPY --from=jni-builder /build/target/classes/native/linux-aarch64/libobijni.so agent/target/classes/native/linux-aarch64/libobijni.so

# Build the project (skip native lib compilation, already done above)
RUN gradle build -x buildNativeLib-amd64 -x buildNativeLib-aarch64 --no-daemon

FROM scratch AS export
COPY --from=builder /build/build/obi-java-agent.jar obi-java-agent.jar
