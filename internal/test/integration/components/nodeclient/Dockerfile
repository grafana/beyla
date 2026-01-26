FROM node:20-slim@sha256:6c51af7dc83f4708aaac35991306bca8f478351cfd2bda35750a62d7efcf05bb

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/nodeclient/client* .

# Run the node app
CMD [ "node", "client.js" ]
