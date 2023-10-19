FROM node:20-slim

# Set the working directory to /build
WORKDIR /

# Copy the source code into the image for building
COPY test/integration/components/nodejsserver .

# Install NodeJS express
RUN npm install express --save

EXPOSE 3030
EXPOSE 3033

# Run the node app
CMD [ "node", "app" ]
