# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.25.6@sha256:ce63a16e0f7063787ebb4eb28e72d477b00b4726f79874b3205a965ffd797ab2 AS builder

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
FROM debian:bookworm-slim@sha256:56ff6d36d4eb3db13a741b342ec466f121480b5edded42e4b7ee850ce7a418ee

WORKDIR /
RUN mkdir -p x509
COPY --from=builder /src/testserver .
COPY --from=builder /src/x509/server_test_cert.pem x509
COPY --from=builder /src/x509/server_test_key.pem x509
USER 0:0

CMD [ "/testserver" ]
