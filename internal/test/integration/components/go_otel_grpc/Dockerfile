# Build the testserver binary
# Docker command must be invoked from the project root directory
FROM golang:1.25.4@sha256:8c945d3e25320e771326dafc6fb72ecae5f87b0f29328cbbd87c4dff506c9135 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY internal/test/integration/components/go_otel_grpc/ .

# Build
RUN go build -o rolldice main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:78d2f66e0fec9e5a39fb2c72ea5e052b548df75602b5215ed01a17171529f706

WORKDIR /
COPY --from=builder /src/rolldice .
USER 0:0

CMD [ "/rolldice" ]