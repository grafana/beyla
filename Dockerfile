# Build the autoinstrumenter binary
ARG GEN_IMG=ghcr.io/open-telemetry/obi-generator:0.2.11@sha256:c9a11deeda1de354aa334817f693efbf5ccee15dcd18caee6a9b221eed0e5773

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
FROM gradle:9.4.1-jdk21-noble@sha256:5a739da3c34646f72da2634b2d4a5e2b467132eaf6abccfb7bc60e1b502d51b5 AS javaagent-builder

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
