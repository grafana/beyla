# Build the manager binary
FROM golang:1.20 as builder

ARG ARCH="amd64"

ENV GOARCH=$ARCH

WORKDIR /opt/app-root

# Copy the go manifests and source
COPY .git/ .git/
COPY bpf/ bpf/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY vendor/ vendor/
COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile

# Build
RUN make compile

# Create final image from minimal + built binary
#TODO: use minimal image
FROM fedora:37
ARG ARCH="amd64"

WORKDIR /
COPY --from=builder /opt/app-root/bin/otelhttp .
USER 0:0

CMD [ "/otelhttp" ]