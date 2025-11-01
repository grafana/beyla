# Description

This test Java (SpringBoot) appserver was adapted from 
[greeting-service](https://github.com/fstab/fosdem-2023), please visit this website for more information.

The test application server has only one API, `/greeting` which can take two optional integer parameters:
- `delay` in milliseconds to override the default 10ms API time delay.
- `response` to change the default HTTP status response code from 200 to something else, e.g. 404.

For example, getting a 404 response with 2 seconds delay can be achieved by calling the API as:

```sh
curl -v "http://localhost:8081/greeting?delay=2000&response=404"
```

# Compiling the sample code

The application can be compiled and run in two separate modes:
- As a SpringBoot Java application
- As a GraalVM Native Image binary

## Pre-requisites

To compile the application you need to have [Apache Maven](https://maven.apache.org/download.cgi) installed. Additionally, if you intend to compile the application as a GraalVM native image, you'll need to install [GraalVM](https://graalvm.github.io/native-build-tools/latest/graalvm-setup.html) separately.

## Compiling the application as a SpringBoot Java application

To compile the application run Maven with package as an option:

```sh
mvn package
```

The application JAR will be created in the auto-generated target directory.

## Compiling the application as a SpringBoot GraalVM Native Image

To compile the application binary directly, run the following command:

```sh
mvn -Pnative native:compile
```

The `greeting-service` binary will be generated in the auto-generated target directory.

To build a `Docker` image of the application binary, run the following command:

```sh
mvn -Pnative spring-boot:build-image
```

# Running the application

The application listens on port `8081`, which can be configured in the `application.properties` file prior to building.

To run the application with the JVM, run the following command:

```sh
java -jar target/greeting-service-1.0.0-SNAPSHOT.jar
```

Running the GraalVM native image directly is as simple as executing the binary, e.g.:

```sh
./target/greeting-service
```

Running the GraalVM Docker container can be done with the following command:

```sh
docker run --rm -p 8081:8081 docker.io/library/greeting-service:1.0.0-SNAPSHOT
```