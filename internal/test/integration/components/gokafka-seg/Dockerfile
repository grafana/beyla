# Build the testserver binary
# Docker command must be invoked from the project root directory
FROM golang:1.25.6@sha256:c1252002e1a0ba34875937d59d4f123d0a4673a50f69c38fca4175cae194c7f9 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY internal/test/integration/components/gokafka-seg/ .

# Build
RUN go build -o testserver main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:78d2f66e0fec9e5a39fb2c72ea5e052b548df75602b5215ed01a17171529f706

WORKDIR /
COPY --from=builder /src/testserver .
USER 0:0

ENV kafkaURL="kafka:9092"
ENV topic="logging"
ENV groupID="1"

CMD [ "/testserver" ]