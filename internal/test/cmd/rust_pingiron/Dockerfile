# Dockerfile that will build a container that runs rust ironssl HTTP on port 8080
FROM rust:latest@sha256:52e36cdd822b813542e13e06a816953234ecad01ebae2d0d7ec4a084c7cda6bd
EXPOSE 8080
RUN mkdir -p /src
COPY src/main.rs /src/main.rs
COPY Cargo.toml /Cargo.toml
COPY Cargo.lock /Cargo.lock
RUN cargo build
CMD ["/target/debug/rust_pingiron"]