FROM ghcr.io/graalvm/native-image:ol8-java17-22 AS javabuilder

# Install tar and gzip to extract the Maven binaries
RUN microdnf update \
 && microdnf install --nodocs \
    tar \
    gzip \
 && microdnf clean all \
 && rm -rf /var/cache/yum

# Install Maven
ARG USER_HOME_DIR="/cache"

ENV JAVA_HOME /usr/lib64/graalvm/graalvm22-ce-java17

# Set the working directory to /home/app
WORKDIR /build

# Copy the source code into the image for building
COPY test/integration/components/javakafka/.mvn .mvn/
COPY test/integration/components/javakafka/mvnw mvnw
COPY test/integration/components/javakafka/src src/
COPY test/integration/components/javakafka/pom.xml pom.xml

RUN java -version
RUN ./mvnw -version

# Build
RUN ./mvnw -Pnative native:compile

# The App Image
FROM debian:bookworm-slim

EXPOSE 8080

# Copy the native executable into the containers
COPY --from=javabuilder /build/target/javakafka ./javakafka
ENTRYPOINT ["/javakafka"]