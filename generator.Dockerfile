FROM golang:alpine3.21 AS base

# Installs dependencies that are required to compile eBPF programs
RUN apk add clang llvm19
RUN apk cache purge
RUN go install github.com/cilium/ebpf/cmd/bpf2go@v0.16.0

VOLUME ["/src"]

WORKDIR /src

FROM base AS builder

RUN cat <<EOF > /generate.sh
#!/bin/sh
export BPF2GO=bpf2go
export BPF_CLANG=clang
export BPF_CFLAGS="-O2 -g -Wall -Werror"

export GENFILES=\$1

if [ -z "\$GENFILES" ]; then
	echo No genfiles specified - regenerating everything
	grep -rlI "BPF2GO" pkg/internal/ | xargs -P 0 -n 1 go generate
else
	cat \$GENFILES | xargs -P 0 -n 1 go generate
fi
EOF

RUN chmod +x /generate.sh

ENTRYPOINT ["/generate.sh"]

