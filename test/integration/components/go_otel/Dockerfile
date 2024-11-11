# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.22 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY test/integration/components/go_otel/ .

# Build
RUN go build -o rolldice main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim

WORKDIR /
COPY --from=builder /src/rolldice .
USER 0:0

CMD [ "/rolldice" ]