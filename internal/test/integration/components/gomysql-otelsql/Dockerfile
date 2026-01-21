# Build the testserver binary
# Docker command must be invoked from the project root directory
FROM golang:1.25.6@sha256:fc24d3881a021e7b968a4610fc024fba749f98fe5c07d4f28e6cfa14dc65a84c AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY go.mod go.mod
COPY gomysql_otelsql.go gomysql_otelsql.go

# Build - download dependencies and build
RUN go mod tidy
RUN go build -o gomysql_otelsql gomysql_otelsql.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:d5d3f9c23164ea16f31852f95bd5959aad1c5e854332fe00f7b3a20fcc9f635c

WORKDIR /
COPY --from=builder /src/gomysql_otelsql .
USER 0:0

CMD [ "/gomysql_otelsql" ]
