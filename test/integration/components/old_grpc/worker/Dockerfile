FROM golang:1.25@sha256:8c945d3e25320e771326dafc6fb72ecae5f87b0f29328cbbd87c4dff506c9135 AS builder

WORKDIR /src

COPY test/integration/components/old_grpc/worker .

RUN make compile

FROM ubuntu:latest@sha256:66460d557b25769b102175144d538d88219c077c678a49af4afca6fbfc1b5252

WORKDIR /
COPY --from=builder /src/bin/worker /worker

ENTRYPOINT ["/worker"]
