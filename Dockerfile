# Build the autoinstrumenter binary
ARG GEN_IMG=ghcr.io/open-telemetry/obi-generator:0.2.3

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
    make generate && \
    make copy-obi-vendor \
    ; fi
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
