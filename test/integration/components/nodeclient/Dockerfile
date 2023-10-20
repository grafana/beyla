FROM node:20-slim

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY test/integration/components/nodeclient/client* . 

# Run the node app
CMD [ "node", "client.js" ]
