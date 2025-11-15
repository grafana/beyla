# Build the testserver binary
# Docker command must be invoked from the project root directory
FROM golang:1.25@sha256:e68f6a00e88586577fafa4d9cefad1349c2be70d21244321321c407474ff9bf2 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY vendor/ vendor/
COPY internal/test/ internal/test/
COPY go.mod go.mod
COPY go.sum go.sum

# Build
RUN go build -o http2client ./internal/test/integration/components/gohttp2/client/main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:936abff852736f951dab72d91a1b6337cf04217b2a77a5eaadc7c0f2f1ec1758

WORKDIR /
COPY --from=builder /src/http2client .
USER 0:0

CMD [ "/http2client" ]