# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.25.3@sha256:6d4e5e74f47db00f7f24da5f53c1b4198ae46862a47395e30477365458347bf2 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY internal/test/integration/components/gomongo/ .

# Build
RUN go build -o testserver main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:7e490910eea2861b9664577a96b54ce68ea3e02ce7f51d89cb0103a6f9c386e0

WORKDIR /
COPY --from=builder /src/testserver .
USER 0:0

CMD [ "/testserver" ]