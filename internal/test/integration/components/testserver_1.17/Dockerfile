# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.17.13@sha256:87262e4a4c7db56158a80a18fefdc4fee5accc41b59cde821e691d05541bbb18 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY internal/test/integration/components/testserver_1.17/ .

# Build
RUN go build -o testserver testserver.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:b4aa902587c2e61ce789849cb54c332b0400fe27b1ee33af4669e1f7e7c3e22f

WORKDIR /
COPY --from=builder /src/testserver .
USER 0:0

CMD [ "/testserver" ]
