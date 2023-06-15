FROM ubuntu:latest AS rustbuilder

RUN apt update
RUN apt install -y build-essential curl pkg-config libssl-dev
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY test/ test/

WORKDIR /build/test/integration/components/rustssltestserver

# Build
RUN cargo build --release

# The App Image
FROM ubuntu:latest

#RUN apt update
#RUN apt install strace -y

EXPOSE 8090

# Copy the native executable into the containers
COPY --from=rustbuilder /build/test/integration/components/rustssltestserver/target/release/greetings ./greetings
COPY --from=rustbuilder /build/test/integration/components/rustssltestserver/key.pem ./key.pem
COPY --from=rustbuilder /build/test/integration/components/rustssltestserver/cert.pem ./cert.pem
ENTRYPOINT ["/greetings"]
#CMD [ "strace", "-f", "/greetings" ]