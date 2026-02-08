# Build the testserver binary
# Docker command must be invoked from the project root directory
FROM golang:1.25.6@sha256:fc24d3881a021e7b968a4610fc024fba749f98fe5c07d4f28e6cfa14dc65a84c AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY go.mod go.mod
COPY go.sum go.sum
COPY gopgx-pool.go gopgx-pool.go

# Build
RUN go mod download
RUN go build -o gopgx-pool gopgx-pool.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe

WORKDIR /
COPY --from=builder /src/gopgx-pool .
USER 0:0

CMD [ "/gopgx-pool" ]

