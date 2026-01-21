# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.25.6@sha256:fc24d3881a021e7b968a4610fc024fba749f98fe5c07d4f28e6cfa14dc65a84c AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY vendor/ vendor/
COPY internal/test/ internal/test/
COPY go.mod go.mod
COPY go.sum go.sum

# Build
RUN go build -o testserver ./internal/test/integration/components/testserver/testserver.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:d5d3f9c23164ea16f31852f95bd5959aad1c5e854332fe00f7b3a20fcc9f635c

WORKDIR /
RUN mkdir -p x509
COPY --from=builder /src/testserver .
COPY --from=builder /src/internal/test/integration/components/testserver/x509/server_test_cert.pem x509
COPY --from=builder /src/internal/test/integration/components/testserver/x509/server_test_key.pem x509
USER 0:0

CMD [ "/testserver" ]
