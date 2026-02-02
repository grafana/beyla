# Build the autoinstrumenter binary
ARG GEN_IMG=ghcr.io/open-telemetry/obi-generator:0.2.6@sha256:440d8777714014e7dc98fecbe2ce96ea827d35f885cfec8861a963b8e41f42cd

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

# OBI's Makefile doesn't let to override BPF2GO env var: temporary hack until we can
ENV TOOLS_DIR=/go/bin

# Build
RUN if [ -z "${DEV_OBI}" ]; then \
    export PATH="/usr/lib/llvm20/bin:$PATH" && \
    make generate && \
    make copy-obi-vendor \
    ; fi
RUN make compile

# Build the Java OBI agent
FROM gradle:9.3.0-jdk21-noble@sha256:c81b8eca24ce89252df6f8e81cb61266d62dbc84ab5f969ea22fc00804f995e2 AS javaagent-builder

WORKDIR /build

RUN apt update
RUN apt install -y clang llvm

# Copy build files
COPY java-vendor/java .

# Build the project
RUN ./gradlew build --no-daemon

# Create final image from minimal + built binary
FROM scratch

LABEL maintainer="Grafana Labs <hello@grafana.com>"

WORKDIR /

COPY --from=javaagent-builder /build/build/obi-java-agent.jar .
COPY --from=builder /src/bin/beyla .
COPY --from=builder /src/LICENSE .
COPY --from=builder /src/NOTICE .
COPY --from=builder /src/third_party_licenses.csv .

COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/beyla" ]
