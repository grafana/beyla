# Development version of the beyla Dockerfile that compiles for coverage
# and allows retrieving coverage files.
# The production-ready minimal image is in the project root's dockerfile.
FROM golang:1.26.10@sha256:672c944cfd07599b5f1bb179869270cdc94c6254e41db4d431259693cb286b82 AS builder

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
COPY internal/test/beyla_extensions/components/beyla/beyla_wrapper.sh /beyla_wrapper.sh

# Build
RUN make compile-for-coverage

# The enrollment tests inspect BPF maps and exercise seccomp fallbacks.
COPY .obi-src/internal/test/integration/components/obi/testtool/ internal/test/obitesttool/
RUN go build -mod=vendor -buildvcs=false -o bin/obitesttool ./internal/test/obitesttool/

# Create final image from minimal + built binary
FROM ubuntu@sha256:678c6550cc43645e08669028bc177f50be4e7c5b8cca677067b1914d4afc7a03

COPY --from=builder /src/bin/beyla /beyla
COPY --from=builder /src/bin/obitesttool /obitesttool
# Wrap the executable in a script that waits for the processes to end
# in order to avoid issues when tearing down the container on kernels 6.14+.
# https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/781
COPY --from=builder /beyla_wrapper.sh /beyla_wrapper.sh
RUN chmod +x /beyla_wrapper.sh

ENTRYPOINT [ "/beyla_wrapper.sh" ]
