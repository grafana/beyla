FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /storefront .

FROM scratch
COPY --from=build /storefront /storefront

EXPOSE 8081
ENTRYPOINT ["/storefront"]
