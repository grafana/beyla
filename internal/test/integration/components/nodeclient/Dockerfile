FROM node:20-slim@sha256:12541e65a3777c6035245518eb43006ed08ca8c684e68cd04ecb4653bdf6cfe1

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/nodeclient/client* . 

# Run the node app
CMD [ "node", "client.js" ]
