FROM debian:bookworm@sha256:6337ad82d5c764a8b6a16cde86b157fdce353e36d8ca06fc1b16d4f34d29960e AS rustbuilder

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
FROM debian:bookworm-slim@sha256:936abff852736f951dab72d91a1b6337cf04217b2a77a5eaadc7c0f2f1ec1758

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