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
ARG MAVEN_DOWNLOAD_URL=https://dlcdn.apache.org/maven/maven-3/3.9.10/binaries/apache-maven-3.9.10-bin.tar.gz

RUN mkdir -p /usr/share/maven /usr/share/maven/ref \
  && curl -L -o /tmp/apache-maven.tar.gz ${MAVEN_DOWNLOAD_URL} \
  && tar -xzf /tmp/apache-maven.tar.gz -C /usr/share/maven --strip-components=1 \
  && rm -f /tmp/apache-maven.tar.gz \
  && ln -s /usr/share/maven/bin/mvn /usr/bin/mvn

ENV JAVA_HOME /usr/lib64/graalvm/graalvm22-ce-java17
ENV MAVEN_HOME /usr/share/maven
ENV MAVEN_CONFIG "$USER_HOME_DIR/.m2"

# Set the working directory to /home/app
WORKDIR /build

# Copy the source code into the image for building
COPY test/integration/components/javatestserver/src src/
COPY test/integration/components/javatestserver/pom.xml pom.xml

RUN java -version
RUN mvn -version

# Build
RUN mvn -Pnative native:compile

# The App Image
FROM debian:bookworm-slim

EXPOSE 8085

# Copy the native executable into the containers
COPY --from=javabuilder /build/target/greeting-service ./greeting
ENTRYPOINT ["/greeting"]