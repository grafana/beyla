# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.25.6@sha256:c1252002e1a0ba34875937d59d4f123d0a4673a50f69c38fca4175cae194c7f9 AS builder

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