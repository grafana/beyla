## Adopted from https://github.com/wbotelhos/how-to-create-a-http-server-with-elixir

FROM elixir:1.19.4-slim@sha256:43bd14f1b4e14dd6b24ef914775ec0f28f0de1e2480544a12a4f0110e4bfe103

WORKDIR /app

# Copy the source code into the image for building
COPY internal/test/integration/components/elixir .

# Install dependencies
RUN mix do deps.get, compile

EXPOSE 4000

# Run the node app
CMD [ "mix", "run", "--no-halt" ]
