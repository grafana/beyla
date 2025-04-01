FROM golang:1.24.1-alpine3.19 AS base

ARG EBPF_VER

# Installs dependencies that are required to compile eBPF programs
RUN apk add clang llvm19 curl
RUN apk cache purge
RUN go install github.com/cilium/ebpf/cmd/bpf2go@$EBPF_VER

VOLUME ["/src"]

WORKDIR /src

FROM base AS builder

ENV BPF_CLANG=clang
ENV BPF_CFLAGS="-O2 -g -Wall -Werror"
ENV BPF2GO=/go/bin/bpf2go
ENV BEYLA_GENFILES_RUN_LOCALLY=1

RUN cat <<EOF > /generate.sh
#!/bin/sh
go run cmd/beyla-genfiles/beyla_genfiles.go
EOF

RUN chmod +x /generate.sh

ENTRYPOINT ["/generate.sh"]

