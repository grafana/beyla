FROM golang:1.26.11@sha256:4165ee6bf3b7811fd7b40373290405c83d0167dcb87ee5f29c427cdcef45ff8f AS builder

WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -o /survey-fixture main.go

FROM scratch
COPY --from=builder /survey-fixture /survey-fixture
COPY --from=builder /survey-fixture /survey-healthcheck
ENTRYPOINT ["/survey-fixture"]
