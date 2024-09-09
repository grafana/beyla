FROM golang:1.23 as builder

WORKDIR /src

COPY test/integration/components/old_grpc/worker .

RUN make compile

FROM ubuntu:latest

WORKDIR /
COPY --from=builder /src/bin/worker /worker

ENTRYPOINT ["/worker"]
