# Build the testserver binary
# Docker command must be invoked from the project root directory
FROM golang:1.25@sha256:f60eaa87c79e604967c84d18fd3b151b3ee3f033bcdade4f3494e38411e60963 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY vendor/ vendor/
COPY internal/test/ internal/test/
COPY go.mod go.mod
COPY go.sum go.sum

# Build
RUN go build -o http2srv ./internal/test/integration/components/gohttp2/server/main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:b4aa902587c2e61ce789849cb54c332b0400fe27b1ee33af4669e1f7e7c3e22f

WORKDIR /
COPY --from=builder /src/http2srv .
COPY --from=builder /src/internal/test/integration/components/gohttp2/server/key.pem .
COPY --from=builder /src/internal/test/integration/components/gohttp2/server/cert.pem .
USER 0:0

CMD [ "/http2srv" ]