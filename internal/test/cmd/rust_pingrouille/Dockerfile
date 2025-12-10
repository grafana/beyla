# Dockerfile that will build a container that runs rust rouille HTTP on port 8080
FROM rust:latest@sha256:867f1d1162913c401378a8504fb17fe2032c760dc316448766f150a130204aad
EXPOSE 8080
RUN mkdir -p /src
COPY src/main.rs /src/main.rs
COPY Cargo.toml /Cargo.toml
COPY Cargo.lock /Cargo.lock
RUN cargo build
CMD ["/target/debug/rust_pingrouille"]