# Build the testserver binary
# Docker command must be invoked from the project root directory
FROM golang:1.25.4@sha256:698183780de28062f4ef46f82a79ec0ae69d2d22f7b160cf69f71ea8d98bf25d AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY go.mod go.mod
COPY go.sum go.sum
COPY gosqlite.go gosqlite.go

# Build
RUN go mod download
RUN go build gosqlite.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:e899040a73d36e2b36fa33216943539d9957cba8172b858097c2cabcdb20a3e2

WORKDIR /
COPY --from=builder /src/gosqlite .
USER 0:0

CMD [ "/gosqlite" ]