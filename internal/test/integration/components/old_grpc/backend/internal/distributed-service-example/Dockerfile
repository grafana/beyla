FROM golang:1.25.6@sha256:fc24d3881a021e7b968a4610fc024fba749f98fe5c07d4f28e6cfa14dc65a84c AS builder

WORKDIR /src

COPY . .

RUN make compile

FROM ubuntu:latest@sha256:c35e29c9450151419d9448b0fd75374fec4fff364a27f176fb458d472dfc9e54

WORKDIR /
COPY --from=builder /src/bin/backend /backend

ENTRYPOINT ["/backend"]
