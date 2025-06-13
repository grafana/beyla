# Build the autoinstrumenter binary
ARG VER=main

FROM ghcr.io/grafana/beyla-ebpf-generator:$VER AS builder

# TODO: embed software version in executable

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

RUN apk add make git bash

# Copy the go manifests and source
COPY .git/ .git/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY vendor/ vendor/
COPY go.mod go.mod
COPY go.sum go.sum
COPY Makefile Makefile
COPY LICENSE LICENSE
COPY NOTICE NOTICE
COPY third_party_licenses.csv third_party_licenses.csv

# Build
RUN make obi-submodule
RUN /generate.sh
RUN make copy-obi-vendor
RUN make compile

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="Grafana Labs <hello@grafana.com>"

WORKDIR /

COPY --from=builder /src/bin/beyla .
COPY --from=builder /src/LICENSE .
COPY --from=builder /src/NOTICE .
COPY --from=builder /src/third_party_licenses.csv .

COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/beyla" ]
