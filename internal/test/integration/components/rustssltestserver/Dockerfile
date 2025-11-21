FROM debian:bookworm@sha256:3d957cd5e0693cf44cbb65aa43033fb701443df6b0afa4dcc9293c9bb7a258f9 AS rustbuilder

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
FROM debian:bookworm-slim@sha256:b4aa902587c2e61ce789849cb54c332b0400fe27b1ee33af4669e1f7e7c3e22f

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