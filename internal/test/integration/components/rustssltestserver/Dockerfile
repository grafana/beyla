FROM debian:bookworm@sha256:23f8d499dcf5559a92ef814c309d747268420cf5e5e60f067f495d509f0aeb93 AS rustbuilder

RUN apt update
RUN apt install -y build-essential curl pkg-config libssl-dev
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/rustssltestserver .
COPY internal/test/integration/components/rusttestserver/large_data.json .

# Build
RUN cargo build --release

# The App Image
FROM debian:bookworm-slim@sha256:56ff6d36d4eb3db13a741b342ec466f121480b5edded42e4b7ee850ce7a418ee

RUN apt update
RUN apt install libssl3 -y
#RUN apt install strace -y

EXPOSE 8490

# Copy the native executable into the containers
COPY --from=rustbuilder /build/target/release/greetings ./greetings
COPY --from=rustbuilder /build/key.pem ./key.pem
COPY --from=rustbuilder /build/cert.pem ./cert.pem
COPY --from=rustbuilder /build/large_data.json ./large_data.json
ENTRYPOINT ["/greetings"]
#CMD [ "strace", "-f", "/greetings" ]
