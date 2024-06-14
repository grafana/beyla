## Adopted from https://github.com/wbotelhos/how-to-create-a-http-server-with-elixir

FROM elixir:1.17.0-slim

WORKDIR /app

# Copy the source code into the image for building
COPY test/integration/components/elixir .

# Install dependencies
RUN mix do deps.get, compile

EXPOSE 4000

# Run the node app
CMD [ "mix", "run", "--no-halt" ]
