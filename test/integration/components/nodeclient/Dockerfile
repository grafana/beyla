FROM node:latest

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY test/ test/

WORKDIR /build/test/integration/components/nodeclient

# Run the node app
CMD [ "node", "client.js" ]
