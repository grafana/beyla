# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.24 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY vendor/ vendor/
COPY test/ test/
COPY go.mod go.mod
COPY go.sum go.sum

# Build
RUN go build -o httppinger ./test/integration/components/httppinger/httppinger.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim

WORKDIR /
COPY --from=builder /src/httppinger .
USER 0:0

CMD [ "/httppinger" ]