# Build the mock OpenAI server binary
# Docker command must be invoked from the project root directory
FROM golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS builder

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
USER 65532:65532

ENV OPENAI_PORT=8081
EXPOSE 8081

CMD [ "/openai-mock" ]
