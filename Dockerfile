# Build the autoinstrumenter binary
FROM golang:1.21 as builder

# TODO: embed software version in executable

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

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
FROM ubuntu:latest

LABEL maintainer="Grafana Labs <hello@grafana.com>"

WORKDIR /
COPY --from=builder /opt/app-root/bin/beyla .
USER 0:0

CMD [ "/beyla" ]