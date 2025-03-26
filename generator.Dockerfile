FROM golang:alpine3.21 AS base

ARG EBPF_VER

# Installs dependencies that are required to compile eBPF programs
RUN apk add clang llvm19 curl
RUN apk cache purge
RUN go install github.com/cilium/ebpf/cmd/bpf2go@$EBPF_VER
COPY cmd/beyla-genfiles/beyla_genfiles.go .
RUN go build -o /go/bin/beyla_genfiles beyla_genfiles.go
RUN go clean -modcache -cache
RUN rm beyla_genfiles.go

VOLUME ["/src"]

WORKDIR /src

FROM base AS builder

RUN cat <<EOF > /generate.sh
#!/bin/sh
export BPF2GO=bpf2go
export BPF_CLANG=clang
export BPF_CFLAGS="-O2 -g -Wall -Werror"
export BEYLA_GENFILES_RUN_LOCALLY=1
export BEYLA_GENFILES_MODULE_ROOT="/src"
beyla_genfiles
EOF

RUN chmod +x /generate.sh

ENTRYPOINT ["/generate.sh"]

