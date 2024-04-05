FROM ubuntu:latest

ARG GOVERSION="1.22.2"

ARG TARGETARCH

RUN echo "using TARGETARCH: $TARGETARCH"

# Installs dependencies that are required to compile eBPF programs
RUN apt update -y
RUN apt install -y curl git linux-headers-generic make llvm clang unzip
RUN apt clean

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

RUN make prereqs

WORKDIR /src

ENTRYPOINT ["make", "generate"]

