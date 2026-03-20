# Build the autoinstrumenter binary
ARG GEN_IMG=ghcr.io/open-telemetry/obi-generator:latest@sha256:b00857fa2cf0c69a7b4c07a079e84ba8b130d26efe8365cc88eb32ec62ea63f7

FROM $GEN_IMG AS builder

# TODO: embed software version in executable

ARG TARGETARCH

# set it to a non-empty value if you are building this image
# from a custom, local OBI repository
# In that case, you must run `make generate copy-obi-vendor`
# manually, before building this image.
# Or directly run`make dev-image-build`
ARG DEV_OBI

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

# Point make to the pre-installed bpf2go binary in the generator image
ENV BPF2GO=/go/bin/bpf2go

# Build
RUN if [ -z "${DEV_OBI}" ]; then \
    export PATH="/usr/lib/llvm20/bin:$PATH" && \
    make generate && \
    make copy-obi-vendor \
    ; fi
RUN make compile

# Build the Java OBI agent
FROM gradle:9.4.0-jdk21-noble@sha256:33ad0e6350d1004ac7def68c4510f62e4d181dbf7e376089ef57175c0400496e AS javaagent-builder

WORKDIR /build

RUN apt update
RUN apt install -y clang llvm

# Copy build files
COPY .obi-src/pkg/internal/java .

# Build the project
RUN gradle build --no-daemon

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="Grafana Labs <hello@grafana.com>"

WORKDIR /

COPY --from=javaagent-builder /build/build/obi-java-agent.jar /src/vendor/go.opentelemetry.io/obi/pkg/internal/java/embedded/obi-java-agent.jar
COPY --from=builder /src/bin/beyla .
COPY --from=builder /src/LICENSE .
COPY --from=builder /src/NOTICE .
COPY --from=builder /src/third_party_licenses.csv .

COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/beyla" ]
