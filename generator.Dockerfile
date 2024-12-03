FROM ubuntu:latest AS base

ARG GOVERSION="1.23.3"

ARG TARGETARCH

RUN echo "using TARGETARCH: $TARGETARCH"

# Installs dependencies that are required to compile eBPF programs
RUN apt update -y
RUN apt install -y curl git linux-headers-generic make llvm clang unzip libbpf-dev libbpf-tools linux-libc-dev linux-bpf-dev
RUN apt clean

# fix some arch-dependant missing include files
FROM base AS base-arm64
RUN ln -s /usr/include/aarch64-linux-gnu/asm /usr/include/asm

FROM base AS base-amd64
RUN ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm

# keeps going by picking up the arch-specific base
FROM base-$TARGETARCH AS builder

VOLUME ["/src"]

WORKDIR /

# Installs a fairly modern distribution of Go
RUN curl -qL https://go.dev/dl/go$GOVERSION.linux-$TARGETARCH.tar.gz -o go.tar.gz
RUN tar -xzf go.tar.gz
RUN rm go.tar.gz

ENV GOROOT /go
RUN mkdir -p /gopath
ENV GOPATH /gopath

ENV GOBIN $GOPATH/bin
ENV PATH $GOROOT/bin:$GOBIN:$PATH
ENV TOOLS_DIR $GOBIN

WORKDIR /tmp
# Copies some pre-required Go dependencies to avoid downloading them on each build
COPY Makefile Makefile
COPY go.mod go.mod

RUN make bpf2go

WORKDIR /src

ENTRYPOINT ["make", "generate"]

