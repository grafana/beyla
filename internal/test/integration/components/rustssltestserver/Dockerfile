FROM debian:bookworm@sha256:26f2a7cab45014541c65f9d140ccfa6aaefbb49686c6759bea9c6f7f5bb3d72f AS rustbuilder

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
FROM debian:bookworm-slim@sha256:78d2f66e0fec9e5a39fb2c72ea5e052b548df75602b5215ed01a17171529f706

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