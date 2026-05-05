# Build JNI native library using Go image (has gcc, no apt install needed)
FROM golang:1.25.9@sha256:8a7adc288b77e9b787cd2695029eb54d10ae80571b21d44fed68d067ad0a9c96 AS jni-builder
ARG BUILDARCH=amd64
COPY --from=gradle:9.4.1-jdk21-noble@sha256:5a739da3c34646f72da2634b2d4a5e2b467132eaf6abccfb7bc60e1b502d51b5 /opt/java/openjdk/include /opt/java/include
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

FROM gradle:9.4.1-jdk21-noble@sha256:5a739da3c34646f72da2634b2d4a5e2b467132eaf6abccfb7bc60e1b502d51b5 AS builder

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
