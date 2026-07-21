ARG GEN_IMG=ghcr.io/open-telemetry/obi-generator:0.2.15@sha256:9cbb1b567377d5779b04e6bcdb87431c77a19e797b4630eba30f5417de96ea33

# Build JNI native library using Go image (has gcc + apt; installs cross-compiler)
FROM golang:1.26.4@sha256:f96cc555eb8db430159a3aa6797cd5bae561945b7b0fe7d0e284c63a3b291609 AS jni-builder
ARG BUILDARCH=amd64
COPY --from=gradle:9.6.1-jdk21-noble@sha256:d3e4ec60a75f6ada80f52e3c648ccfcbeaff4bc0d8e0f5ce55f81994763daf3c /opt/java/openjdk/include /opt/java/include
WORKDIR /build
COPY .obi-src/pkg/internal/java/agent/src/main/c/ src/main/c/
COPY .obi-src/pkg/internal/java/agent/Makefile.jni Makefile.jni

# Install the cross-compiler for the non-native architecture
RUN apt-get update && \
    case "$BUILDARCH" in \
      amd64) apt-get install -y gcc-aarch64-linux-gnu ;; \
      arm64) apt-get install -y gcc-x86-64-linux-gnu ;; \
    esac

# Build for own architecture
RUN case "$BUILDARCH" in \
      amd64) SLUG=linux-amd64 ;; \
      arm64) SLUG=linux-aarch64 ;; \
    esac && \
    make -f Makefile.jni CC=gcc JAVA_HOME=/opt/java JNI_HEADERS_DIR=src/main/c BUILD_DIR=build/jni/$SLUG TARGET_DIR=target/classes/native/$SLUG

# Cross-compile for the other architecture
RUN case "$BUILDARCH" in \
      amd64) CC=aarch64-linux-gnu-gcc; SLUG=linux-aarch64 ;; \
      arm64) CC=x86_64-linux-gnu-gcc;  SLUG=linux-amd64 ;; \
    esac && \
    make -f Makefile.jni CC=$CC JAVA_HOME=/opt/java JNI_HEADERS_DIR=src/main/c BUILD_DIR=build/jni/$SLUG TARGET_DIR=target/classes/native/$SLUG

# Build the Java OBI agent
FROM gradle:9.6.1-jdk21-noble@sha256:d3e4ec60a75f6ada80f52e3c648ccfcbeaff4bc0d8e0f5ce55f81994763daf3c AS javaagent-builder

WORKDIR /build

# Copy build files
COPY .obi-src/pkg/internal/java .
# Apply Beyla-specific Java patches on top of OBI source
COPY internal/java/ .

# Pre-built native library from jni-builder stage
COPY --from=jni-builder /build/target/classes/native/linux-amd64/libobijni.so  agent/target/classes/native/linux-amd64/libobijni.so
COPY --from=jni-builder /build/target/classes/native/linux-aarch64/libobijni.so agent/target/classes/native/linux-aarch64/libobijni.so

# Build the project (skip native lib compilation, already done above)
RUN gradle build -x buildNativeLib-amd64 -x buildNativeLib-aarch64 --no-daemon

# Build the autoinstrumenter binary
FROM $GEN_IMG AS builder

# TODO: embed software version in executable

ARG TARGETARCH

# set it to a non-empty value if you are building this image
# from a custom, local OBI repository
# In that case, you must run `make generate copy-obi-vendor`
# manually, before building this image.
# Or directly run`make dev-image-build`
ARG DEV_OBI

ENV GOARCH=$TARGETARCH

WORKDIR /src

RUN apk add make git bash

# Copy the go manifests and source
COPY .git/ .git/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY vendor/ vendor/
COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile
COPY LICENSE LICENSE
COPY NOTICE NOTICE
COPY third_party_licenses.csv third_party_licenses.csv

# Point make to the pre-installed bpf2go binary in the generator image
ENV BPF2GO=/go/bin/bpf2go

# Build
RUN if [ -z "${DEV_OBI}" ]; then \
    /generate.sh && \
    make copy-obi-vendor \
    ; fi

# The Java agent is embedded at Go compile time, so the platform-specific jar
# must be copied into vendor before building the Beyla binary.
COPY --from=javaagent-builder /build/build/obi-java-agent.jar /src/vendor/go.opentelemetry.io/obi/pkg/internal/java/embedded/obi-java-agent.jar
RUN make compile

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="Grafana Labs <hello@grafana.com>"

WORKDIR /

COPY --from=builder /src/bin/beyla .
COPY --from=builder /src/LICENSE .
COPY --from=builder /src/NOTICE .
COPY --from=builder /src/third_party_licenses.csv .

COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/beyla" ]
