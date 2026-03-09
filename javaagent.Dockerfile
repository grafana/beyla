FROM gradle:9.4.0-jdk21-noble@sha256:33ad0e6350d1004ac7def68c4510f62e4d181dbf7e376089ef57175c0400496e AS builder

RUN apt update
RUN apt install -y clang llvm

WORKDIR /build

# Copy build files
COPY .obi-src/pkg/internal/java .

# Build the project
RUN ./gradlew build --no-daemon

FROM scratch AS export
COPY --from=builder /build/build/obi-java-agent.jar /obi-java-agent.jar