# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.21 as builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY vendor/ vendor/
COPY test/ test/
COPY go.mod go.mod
COPY go.sum go.sum

# Build
RUN go build -o testserver ./test/integration/components/testserver/testserver.go

# Create final image from minimal + built binary
#TODO: use minimal image
FROM ubuntu:latest

WORKDIR /
COPY --from=builder /src/testserver .
USER 0:0

CMD [ "/testserver" ]