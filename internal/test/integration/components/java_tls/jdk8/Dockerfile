FROM maven:3.9.12-amazoncorretto-8-debian@sha256:7a9eadac3edbf887e5c1863a0eba923bbaf7cb561400db72917eed987078976a AS javabuilder

# Install tar and gzip to extract the Maven binaries
RUN apt install -y tar gzip

# Install Maven
ARG USER_HOME_DIR="/cache"

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/java_tls/jdk8/src src/
COPY internal/test/integration/components/java_tls/jdk8/pom.xml pom.xml

RUN java -version
RUN mvn -version

# Build
RUN mvn clean package

# The App Image
FROM eclipse-temurin:8u472-b08-jre-noble@sha256:d3a855bd7eee6011f8c60ea06481984e2d6d5b8ac7dfcab361c574cf830d4a5b

EXPOSE 8080

COPY --from=javabuilder /build/target/greeting-service-1.0.0-SNAPSHOT.jar .
CMD [ "java", "-jar", "/greeting-service-1.0.0-SNAPSHOT.jar" ]
