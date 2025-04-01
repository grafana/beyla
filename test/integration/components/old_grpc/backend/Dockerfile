FROM golang:1.24 AS builder

WORKDIR /src

COPY test/integration/components/old_grpc/backend .

RUN make compile

FROM ubuntu:latest

WORKDIR /
COPY --from=builder /src/bin/backend /backend

ENTRYPOINT ["/backend"]
