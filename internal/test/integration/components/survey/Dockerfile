FROM golang:1.26.10@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS builder

WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -o /survey-fixture main.go

FROM scratch
COPY --from=builder /survey-fixture /survey-fixture
COPY --from=builder /survey-fixture /survey-healthcheck
ENTRYPOINT ["/survey-fixture"]
