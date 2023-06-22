FROM node:latest

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY test/ test/

WORKDIR /build/test/integration/components/nodejsserver

# Install NodeJS express
RUN npm install express --save

EXPOSE 3030

# Run the node app
CMD [ "node", "app" ]
