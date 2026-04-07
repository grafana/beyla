FROM gradle:9.4.1-jdk21-noble@sha256:4a19481c230d8b5d41f17ea0c3cb9633f566be9ce498dccdb75aaa1282275f9f AS builder

RUN apt update
RUN apt install -y clang llvm

WORKDIR /build

# Copy build files
COPY .obi-src/pkg/internal/java .

# Build the project
RUN gradle build --no-daemon

FROM scratch AS export
COPY --from=builder /build/build/obi-java-agent.jar vendor/go.opentelemetry.io/obi/pkg/internal/java/embedded/obi-java-agent.jar