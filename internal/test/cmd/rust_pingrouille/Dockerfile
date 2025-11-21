# Dockerfile that will build a container that runs rust rouille HTTP on port 8080
FROM rust:latest@sha256:ad8c72c693b517ed60c930839daed91a5696fa6118f031d888cd0b7055a921a3
EXPOSE 8080
RUN mkdir -p /src
COPY src/main.rs /src/main.rs
COPY Cargo.toml /Cargo.toml
COPY Cargo.lock /Cargo.lock
RUN cargo build
CMD ["/target/debug/rust_pingrouille"]