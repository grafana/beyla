FROM golang:1.26.10@sha256:cfa27959837144bf4649802ba38e59daffd0dd2a7994aa83daaf113285b0f551 AS builder

WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -o /survey-fixture main.go

FROM scratch
COPY --from=builder /survey-fixture /survey-fixture
COPY --from=builder /survey-fixture /survey-healthcheck
ENTRYPOINT ["/survey-fixture"]
