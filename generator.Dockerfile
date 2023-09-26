FROM fedora:37

ARG GOVERSION="1.21.1"

ARG TARGETARCH

RUN echo "using TARGETARCH: $TARGETARCH"

# Installs dependencies that are required to compile eBPF programs
RUN dnf install -y git kernel-devel make llvm clang unzip
RUN dnf clean all

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
RUN make prereqs

WORKDIR /src

ENTRYPOINT ["make", "generate"]

