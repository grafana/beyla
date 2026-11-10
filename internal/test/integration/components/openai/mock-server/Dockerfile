# Build the mock OpenAI server binary
# Docker command must be invoked from the project root directory
FROM golang:1.26.10@sha256:cfa27959837144bf4649802ba38e59daffd0dd2a7994aa83daaf113285b0f551 AS builder

ARG TARGETARCH

ENV GOARCH=$TARGETARCH

WORKDIR /src

# Copy the go manifests and source
COPY main.go main.go

# Build
RUN go build -o openai-mock main.go

# Create final image from minimal + built binary
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

WORKDIR /
COPY --from=builder /src/openai-mock .
USER 0:0

ENV OPENAI_PORT=8081
EXPOSE 8081

CMD [ "/openai-mock" ]
