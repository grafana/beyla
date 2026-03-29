FROM gradle:9.4.1-jdk21-noble@sha256:7ca3db170906c970153cd3a576ddb42ec3cedc4e6f1dbb2228547e286fa5c3b4 AS builder

RUN apt update
RUN apt install -y clang llvm

WORKDIR /build

# Copy build files
COPY .obi-src/pkg/internal/java .

# Build the project
RUN gradle build --no-daemon

FROM scratch AS export
COPY --from=builder /build/build/obi-java-agent.jar vendor/go.opentelemetry.io/obi/pkg/internal/java/embedded/obi-java-agent.jar