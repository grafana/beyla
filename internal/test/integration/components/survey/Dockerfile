FROM golang:1.26.8@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS builder

WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -o /survey-fixture main.go

FROM scratch
COPY --from=builder /survey-fixture /survey-fixture
COPY --from=builder /survey-fixture /survey-healthcheck
ENTRYPOINT ["/survey-fixture"]
