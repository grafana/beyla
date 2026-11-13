FROM golang:1.27.3@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS builder

WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -o /survey-fixture main.go

FROM scratch
COPY --from=builder /survey-fixture /survey-fixture
COPY --from=builder /survey-fixture /survey-healthcheck
ENTRYPOINT ["/survey-fixture"]
