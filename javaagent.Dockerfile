FROM gradle:9.4.1-jdk21-noble@sha256:5a739da3c34646f72da2634b2d4a5e2b467132eaf6abccfb7bc60e1b502d51b5 AS builder

RUN apt update
RUN apt install -y clang llvm

WORKDIR /build

# Copy build files
COPY .obi-src/pkg/internal/java .

# Build the project
RUN gradle build --no-daemon

FROM scratch AS export
COPY --from=builder /build/build/obi-java-agent.jar vendor/go.opentelemetry.io/obi/pkg/internal/java/embedded/obi-java-agent.jar