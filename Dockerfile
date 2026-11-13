ARG RUNTIME_IMG=scratch
ARG GEN_IMG=ghcr.io/open-telemetry/obi-generator:0.2.18@sha256:00da54aef610c9d8ed77757afab9c419079f17852bad0e02fe0102e5ce508be4

# Build JNI native library using Go image (has gcc + apt; installs cross-compiler)
FROM golang:1.26.10@sha256:672c944cfd07599b5f1bb179869270cdc94c6254e41db4d431259693cb286b82 AS jni-builder
ARG BUILDARCH=amd64
COPY --from=gradle:9.6.1-jdk21-noble@sha256:8074080ea0c9d663076211abc189ba1472474d3019a0da49c4216dce3184cf85 /opt/java/openjdk/include /opt/java/include
WORKDIR /build
COPY .obi-src/pkg/internal/java/agent/src/main/c/ src/main/c/
COPY .obi-src/pkg/internal/java/agent/Makefile.jni Makefile.jni

# Install the cross-compiler for the non-native architecture
# Track current Debian security updates rather than pinning package versions
# that can disappear from the archive.
# hadolint ignore=DL3008
RUN apt-get update && \
    case "$BUILDARCH" in \
      amd64) apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross ;; \
      arm64) apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu libc6-dev-amd64-cross ;; \
    esac

# Build for own architecture
RUN case "$BUILDARCH" in \
      amd64) SLUG=linux-amd64 ;; \
      arm64) SLUG=linux-aarch64 ;; \
    esac && \
    make -f Makefile.jni CC=gcc JAVA_HOME=/opt/java JNI_HEADERS_DIR=src/main/c BUILD_DIR="build/jni/$SLUG" TARGET_DIR="target/classes/native/$SLUG"

# Cross-compile for the other architecture
# Keep the cross build in its own layer so BuildKit can reuse the native
# output when only the cross-build command changes.
# hadolint ignore=DL3059
RUN case "$BUILDARCH" in \
      amd64) CC=aarch64-linux-gnu-gcc; SLUG=linux-aarch64 ;; \
      arm64) CC=x86_64-linux-gnu-gcc;  SLUG=linux-amd64 ;; \
    esac && \
    make -f Makefile.jni CC="$CC" JAVA_HOME=/opt/java JNI_HEADERS_DIR=src/main/c BUILD_DIR="build/jni/$SLUG" TARGET_DIR="target/classes/native/$SLUG"

# Build the Java OBI agent
FROM gradle:9.6.1-jdk21-noble@sha256:8074080ea0c9d663076211abc189ba1472474d3019a0da49c4216dce3184cf85 AS javaagent-builder

WORKDIR /build

# Copy build files
COPY .obi-src/pkg/internal/java .
# Apply Beyla-specific Java patches on top of OBI source
COPY internal/java/agent/ agent/

# Pre-built native library from jni-builder stage
COPY --from=jni-builder /build/target/classes/native/linux-amd64/libobijni.so  agent/target/classes/native/linux-amd64/libobijni.so
COPY --from=jni-builder /build/target/classes/native/linux-aarch64/libobijni.so agent/target/classes/native/linux-aarch64/libobijni.so

# Build the project (skip native lib compilation, already done above)
RUN gradle build -x buildNativeLib-amd64 -x buildNativeLib-aarch64 --no-daemon

# Build the autoinstrumenter binary
FROM $GEN_IMG AS builder

# Select the Go toolchain required by Beyla's go.mod.
ENV GOTOOLCHAIN=auto

# TODO: embed software version in executable

ARG TARGETARCH

# set it to a non-empty value if you are building this image
# from a custom, local OBI repository
# In that case, regenerate the OBI sources and vendor dependencies with
# `mise run vendor:obi` before building this image.
# Or directly run the development image build task.
ARG DEV_OBI

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Use the current patched packages from the pinned generator image's Alpine
# repositories; exact package versions are not stable in rolling repositories.
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates curl git bash make

# The generator image provides Go, bpf2go, and Clang. Copy only Mise metadata
# so repository tasks can run without installing a second Go toolchain.
COPY --from=ghcr.io/jdx/mise:2026.11.4@sha256:085be191bbe51dbe93894681b7f29f6c014ae267e7a365c0b8b6a2fdd882ac63 /usr/local/bin/mise /usr/local/bin/mise
ENV MISE_ENABLE_TOOLS=none

# Copy the go manifests and source
COPY .git/ .git/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY bpf/ bpf/
COPY vendor/ vendor/
COPY go.mod go.mod
COPY go.sum go.sum
COPY .obi-src/ .obi-src/
COPY mise.toml mise.lock ./
COPY .mise/ .mise/
COPY internal/java/mise.toml internal/java/
COPY internal/java/.mise/ internal/java/.mise/
COPY internal/test/oats/mise.toml internal/test/oats/
COPY Makefile Makefile
COPY scripts/obi-configbridge/ scripts/obi-configbridge/
COPY LICENSE LICENSE
COPY NOTICE NOTICE
COPY third_party_licenses.csv third_party_licenses.csv

# The generator image already provides these pinned build tools. Mise supplies
# the task graph and environment without downloading a duplicate Go toolchain.

# .obi-src is a worktree; its .git file points to a host path that is not
# present in the image, so remove that pointer before running its Makefile.
# Build
RUN if [ -z "${DEV_OBI}" ]; then \
    rm -f .obi-src/.git && \
    for llvm_bin in /usr/lib/llvm*/bin; do PATH="$llvm_bin:$PATH"; done; \
    export PATH && \
    make -C .obi-src generate BPF2GO=/go/bin/bpf2go && \
    BPF2GO=/go/bin/bpf2go BPF_CLANG=clang mise run --skip-tools --skip-deps generate:beyla && \
    go mod vendor; \
    fi

# The Java agent is embedded at Go compile time, so the platform-specific jar
# must be copied into vendor before building the Beyla binary.
COPY --from=javaagent-builder /build/build/obi-java-agent.jar /src/vendor/go.opentelemetry.io/obi/pkg/internal/java/embedded/obi-java-agent.jar
ARG BUILD_TAGS
RUN mise run --skip-tools compile

# Create final image from minimal + built binary
FROM ${RUNTIME_IMG}

LABEL maintainer="Grafana Labs <hello@grafana.com>"

WORKDIR /

COPY --from=builder /src/bin/beyla .
COPY --from=builder /src/LICENSE .
COPY --from=builder /src/NOTICE .
COPY --from=builder /src/third_party_licenses.csv .

COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/beyla" ]
