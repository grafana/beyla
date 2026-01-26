## Adopted from https://github.com/wbotelhos/how-to-create-a-http-server-with-elixir

FROM elixir:1.19.5-slim@sha256:b3f6cba9b8fab0c0587fd899e0b1f77c4870a2cf4ba45b3f64e6de2a4d02fa72

WORKDIR /app

# Copy the source code into the image for building
COPY internal/test/integration/components/elixir .

# Install dependencies
RUN mix do deps.get, compile

EXPOSE 4000

# Run the node app
CMD [ "mix", "run", "--no-halt" ]
