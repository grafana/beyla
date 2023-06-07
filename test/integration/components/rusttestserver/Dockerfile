FROM rust:latest AS rustbuilder

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY test/ test/

WORKDIR /build/test/integration/components/rusttestserver

# Build
RUN cargo build --release

# The App Image
FROM ubuntu:latest

EXPOSE 8090

# Copy the native executable into the containers
COPY --from=rustbuilder /build/test/integration/components/rusttestserver/target/release/greetings ./greetings
ENTRYPOINT ["/greetings"]