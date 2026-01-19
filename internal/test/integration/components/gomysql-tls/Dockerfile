# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.25.6@sha256:c1252002e1a0ba34875937d59d4f123d0a4673a50f69c38fca4175cae194c7f9 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY go.mod go.mod
COPY go.sum go.sum
COPY gomysql.go gomysql.go

# Build
RUN go mod download
RUN go build -o gomysql gomysql.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:b4aa902587c2e61ce789849cb54c332b0400fe27b1ee33af4669e1f7e7c3e22f

WORKDIR /
COPY --from=builder /src/gomysql .
USER 0:0

CMD [ "/gomysql" ]
