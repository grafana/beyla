FROM maven:3.9.12-eclipse-temurin-21@sha256:7d8cf78b43f2733e53bcf19fbe8c57d9831c7b303dfb72ee3b60a3b9fda6c251 AS javabuilder

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
FROM eclipse-temurin:21.0.9_10-jre@sha256:d45e4719da1774b3abde398867f78a6d9b9afe4265f574f3d54062f6daeb00b3

EXPOSE 8080

# Copy the native executable into the containers
COPY --from=javabuilder /build/target/http-client-demo-1.0.0.jar .
CMD [ "java", "-jar", "/http-client-demo-1.0.0.jar" ]
