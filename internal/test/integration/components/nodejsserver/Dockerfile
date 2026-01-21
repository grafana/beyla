FROM node:20-slim@sha256:a270640213033657548b7ed57852709a0d2ee3b277f902f912367216aa8e9520

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY internal/test/integration/components/nodejsserver .

# Install NodeJS express
RUN npm install express --save

EXPOSE 3030
EXPOSE 3033

# Run the node app
CMD [ "node", "app" ]
