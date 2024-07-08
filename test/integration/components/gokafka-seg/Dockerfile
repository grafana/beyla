# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.22 as builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY test/integration/components/gokafka/ .

# Build
RUN go build -o testserver main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim

WORKDIR /
COPY --from=builder /src/testserver .
USER 0:0

ENV kafkaURL="127.0.0.1:9093"
ENV topic="logging"
ENV groupID="1"

CMD [ "/testserver" ]