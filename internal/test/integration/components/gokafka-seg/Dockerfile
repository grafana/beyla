# Build the testserver binary
# Docker command must be invoked from the project root directory
FROM golang:1.25.4@sha256:698183780de28062f4ef46f82a79ec0ae69d2d22f7b160cf69f71ea8d98bf25d AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY internal/test/integration/components/gokafka-seg/ .

# Build
RUN go build -o testserver main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:e899040a73d36e2b36fa33216943539d9957cba8172b858097c2cabcdb20a3e2

WORKDIR /
COPY --from=builder /src/testserver .
USER 0:0

ENV kafkaURL="kafka:9092"
ENV topic="logging"
ENV groupID="1"

CMD [ "/testserver" ]