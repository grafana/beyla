# Development version of the beyla Dockerfile that compiles for coverage
# and allows retrieving coverage files.
# The production-ready minimal image is in the project root's dockerfile.
FROM golang:1.26.4@sha256:32c0e6e5c4f6707717051091b4d0b077464a679eaab563e11474efc5328e2aa5 AS builder

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
