# Development version of the beyla Dockerfile that compiles for coverage
# and allows retrieving coverage files.
# The production-ready minimal image is in the project root's dockerfile.
FROM golang:1.25.6@sha256:c1252002e1a0ba34875937d59d4f123d0a4673a50f69c38fca4175cae194c7f9 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY .git/ .git/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY vendor/ vendor/
COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile

# Build
RUN make compile-cache-for-coverage

# Create final image from minimal + built binary
FROM scratch

WORKDIR /
COPY --from=builder /src/bin/k8s-cache .

ENTRYPOINT [ "/k8s-cache" ]