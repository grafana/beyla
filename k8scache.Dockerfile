# Build the binary for the k8s-cache service
FROM golang:1.26.10@sha256:672c944cfd07599b5f1bb179869270cdc94c6254e41db4d431259693cb286b82 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/jdx/mise:2026.11.4@sha256:085be191bbe51dbe93894681b7f29f6c014ae267e7a365c0b8b6a2fdd882ac63 /usr/local/bin/mise /usr/local/bin/mise
ENV MISE_ENABLE_TOOLS=none

ARG TARGETARCH
ENV GOARCH=$TARGETARCH

WORKDIR /opt/app-root

# Copy the go manifests and source
COPY go.mod go.mod
COPY go.sum go.sum
COPY LICENSE LICENSE
COPY NOTICE NOTICE
COPY mise.toml mise.lock ./
COPY .mise/ .mise/
COPY internal/java/mise.toml internal/java/
COPY internal/java/.mise/ internal/java/.mise/
COPY internal/test/oats/mise.toml internal/test/oats/
COPY third_party_licenses.csv third_party_licenses.csv
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY vendor/ vendor/
COPY .git/ .git/

# Build
RUN mise run --skip-tools compile:cache

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="Grafana Labs <hello@grafana.com>"

WORKDIR /

COPY --from=builder /opt/app-root/bin/k8s-cache .
COPY --from=builder /opt/app-root/LICENSE .
COPY --from=builder /opt/app-root/NOTICE .
COPY --from=builder /opt/app-root/third_party_licenses.csv .

ENTRYPOINT [ "/k8s-cache" ]
