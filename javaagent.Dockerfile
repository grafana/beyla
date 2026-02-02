FROM gradle:9.3.0-jdk21-noble@sha256:c81b8eca24ce89252df6f8e81cb61266d62dbc84ab5f969ea22fc00804f995e2 AS builder

RUN apt update
RUN apt install -y clang llvm

WORKDIR /build

# Copy build files
COPY .obi-src/pkg/internal/java .

# Build the project
RUN ./gradlew build --no-daemon

FROM scratch AS export
COPY --from=builder /build/build/obi-java-agent.jar /obi-java-agent.jar