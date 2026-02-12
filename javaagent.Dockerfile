FROM gradle:9.3.1-jdk21-noble@sha256:5f836f4642496f816f15d495b007e1912f36bf58fbea0247c0b761af438d7cf2 AS builder

RUN apt update
RUN apt install -y clang llvm

WORKDIR /build

# Copy build files
COPY .obi-src/pkg/internal/java .

# Build the project
RUN ./gradlew build --no-daemon

FROM scratch AS export
COPY --from=builder /build/build/obi-java-agent.jar /obi-java-agent.jar