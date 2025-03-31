# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.24 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY go.mod go.mod
COPY go.sum go.sum
COPY gosql.go gosql.go

# Build
RUN go mod download
RUN go build -o gosql gosql.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim

WORKDIR /
COPY --from=builder /src/gosql .
USER 0:0

CMD [ "/gosql" ]