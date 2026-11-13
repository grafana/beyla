FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 as builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

RUN apk add --no-cache ca-certificates curl git bash
COPY --from=ghcr.io/jdx/mise:2026.11.4@sha256:085be191bbe51dbe93894681b7f29f6c014ae267e7a365c0b8b6a2fdd882ac63 /usr/local/bin/mise /usr/local/bin/mise
ENV MISE_ENABLE_TOOLS=none

# Copy the go manifests and source
COPY .git/ .git/
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY vendor/ vendor/
COPY go.mod go.mod
COPY go.sum go.sum
COPY mise.toml mise.lock ./
COPY .mise/ .mise/
COPY internal/java/mise.toml internal/java/
COPY internal/java/.mise/ internal/java/.mise/
COPY internal/test/oats/mise.toml internal/test/oats/
COPY LICENSE LICENSE
COPY NOTICE NOTICE
COPY third_party_licenses.csv third_party_licenses.csv

RUN go install github.com/go-delve/delve/cmd/dlv@latest

# Prior to using this debug.Dockerfile, regenerate eBPF sources and vendor dependencies.
RUN mise run --skip-tools compile:debug

FROM alpine:latest@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

WORKDIR /

COPY --from=builder /go/bin/dlv /
COPY --from=builder /src/bin/beyla /
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/dlv", "--listen=:2345", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "/beyla" ]
