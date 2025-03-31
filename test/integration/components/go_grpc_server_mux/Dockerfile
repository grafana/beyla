# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.24 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY go.mod go.mod
COPY go.sum go.sum
COPY main.go main.go
COPY x509/server_test_cert.pem x509/server_test_cert.pem
COPY x509/server_test_key.pem x509/server_test_key.pem


# Build
RUN go build -o testserver main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim

WORKDIR /
RUN mkdir -p x509
COPY --from=builder /src/testserver .
COPY --from=builder /src/x509/server_test_cert.pem x509
COPY --from=builder /src/x509/server_test_key.pem x509
USER 0:0

CMD [ "/testserver" ]