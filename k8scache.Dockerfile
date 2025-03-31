# Build the binary for the k8s-cache service
FROM golang:1.24 AS builder

ARG TARGETARCH
ENV GOARCH=$TARGETARCH

WORKDIR /opt/app-root

# Copy the go manifests and source
COPY go.mod go.mod
COPY go.sum go.sum
COPY LICENSE LICENSE
COPY NOTICE NOTICE
COPY Makefile Makefile
COPY third_party_licenses.csv third_party_licenses.csv
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY vendor/ vendor/
COPY .git/ .git/

# Build
RUN make compile-cache

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="Grafana Labs <hello@grafana.com>"

WORKDIR /

COPY --from=builder /opt/app-root/bin/k8s-cache .
COPY --from=builder /opt/app-root/LICENSE .
COPY --from=builder /opt/app-root/NOTICE .
COPY --from=builder /opt/app-root/third_party_licenses.csv .

ENTRYPOINT [ "/k8s-cache" ]