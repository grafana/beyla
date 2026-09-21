FROM golang:1.24-alpine AS build

WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /legacy-api .

FROM scratch
COPY --from=build /legacy-api /legacy-api

EXPOSE 8083
ENTRYPOINT ["/legacy-api"]
