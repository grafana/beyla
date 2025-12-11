FROM node:20-slim@sha256:1b38aaddff63cd0d3a9b5b03863a71fd33ee62047dd2e915f494d96b4b9c18cc

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
