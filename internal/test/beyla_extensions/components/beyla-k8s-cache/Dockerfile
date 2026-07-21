# Development version of the beyla Dockerfile that compiles for coverage
# and allows retrieving coverage files.
# The production-ready minimal image is in the project root's dockerfile.
FROM golang:1.26.4@sha256:f96cc555eb8db430159a3aa6797cd5bae561945b7b0fe7d0e284c63a3b291609 AS builder

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
COPY Makefile Makefile

# Build
RUN make compile-cache-for-coverage

# Create final image from minimal + built binary
FROM scratch

WORKDIR /
COPY --from=builder /src/bin/k8s-cache .

ENTRYPOINT [ "/k8s-cache" ]
