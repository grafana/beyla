FROM maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237 AS javabuilder

# Install tar and gzip to extract the Maven binaries
RUN apt install -y tar gzip

# Install Maven
ARG USER_HOME_DIR="/cache"

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/java_tls/sync_async_tls/src src/
COPY internal/test/integration/components/java_tls/sync_async_tls/pom.xml pom.xml

RUN java -version
RUN mvn -version

# Build
RUN mvn clean package

# The App Image
FROM eclipse-temurin:21.0.9_10-jre@sha256:b0f6befb3f2af49704998c4425cb6313c1da505648a8e78cee731531996f735d

EXPOSE 8080

# Copy the native executable into the containers
COPY --from=javabuilder /build/target/greeting-service-1.0.0.jar .
CMD [ "java", "-jar", "/greeting-service-1.0.0.jar" ]