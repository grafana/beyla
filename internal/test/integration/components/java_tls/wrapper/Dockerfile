# Build the testserver binary
# Docker command must be invoked from the projec root directory
FROM golang:1.25.5@sha256:20b91eda7a9627c127c0225b0d4e8ec927b476fa4130c6760928b849d769c149 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY go.mod go.mod
COPY go.sum go.sum
COPY wrapper.go wrapper.go

# Build
RUN go mod download
RUN go build -o wrapper wrapper.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:b4aa902587c2e61ce789849cb54c332b0400fe27b1ee33af4669e1f7e7c3e22f

WORKDIR /
COPY --from=builder /src/wrapper .
USER 0:0

CMD [ "/wrapper" ]