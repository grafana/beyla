FROM node:20-slim

WORKDIR /app

COPY test/integration/components/nodemultiproc/package*.json ./
RUN npm install

COPY test/integration/components/nodemultiproc/service.js .
COPY test/integration/components/nodemultiproc/start-all.js .

EXPOSE 5000 5001 5002 5003

CMD [ "node", "start-all.js" ]

