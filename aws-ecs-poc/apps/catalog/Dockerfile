FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /catalog .

FROM scratch
COPY --from=build /catalog /catalog

EXPOSE 8082
ENTRYPOINT ["/catalog"]
