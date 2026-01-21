FROM maven:3.9.12-eclipse-temurin-21@sha256:5ab44df1a8d34911d649713c1f451efc0b7ddea3305f09eb7070fdbb188c51ba AS javabuilder
# Install tar and gzip to extract the Maven binaries
RUN apt install -y tar gzip

# Install Maven
ARG USER_HOME_DIR="/cache"

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/java_tls/netty_tls/src src/
COPY internal/test/integration/components/java_tls/netty_tls/pom.xml pom.xml

RUN java -version
RUN mvn -version

# Build
RUN mvn clean package

# The App Image
FROM eclipse-temurin:21.0.9_10-jre@sha256:b0f6befb3f2af49704998c4425cb6313c1da505648a8e78cee731531996f735d

EXPOSE 8080

# Copy the native executable into the containers
COPY --from=javabuilder /build/target/http-client-demo-1.0.0.jar .
CMD [ "java", "-jar", "/http-client-demo-1.0.0.jar" ]
