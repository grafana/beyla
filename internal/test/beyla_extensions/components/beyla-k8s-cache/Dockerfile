# Development version of the beyla Dockerfile that compiles for coverage
# and allows retrieving coverage files.
# The production-ready minimal image is in the project root's dockerfile.
FROM golang:1.26.11@sha256:4165ee6bf3b7811fd7b40373290405c83d0167dcb87ee5f29c427cdcef45ff8f AS builder

# Track current security updates from the pinned Debian base's package mirror.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/jdx/mise:2026.11.11@sha256:14a30b9945ea5c2fbae70d8b6be8f2c8b2456698f2a258f3f6315f7784c84676 /usr/local/bin/mise /usr/local/bin/mise
ENV MISE_ENABLE_TOOLS=none

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY .git/ .git/
COPY vendor/ vendor/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY go.mod go.mod
COPY go.sum go.sum
COPY mise.toml mise.lock ./
COPY .mise/ .mise/
COPY internal/java/mise.toml internal/java/mise.lock internal/java/
COPY internal/java/.mise/ internal/java/.mise/
COPY internal/test/oats/mise.toml internal/test/oats/

# Build
RUN mise run --skip-tools compile:cache-coverage

# Create final image from minimal + built binary
FROM scratch

WORKDIR /
COPY --from=builder /src/bin/k8s-cache .

ENTRYPOINT [ "/k8s-cache" ]
