FROM node:20-slim@sha256:a270640213033657548b7ed57852709a0d2ee3b277f902f912367216aa8e9520

WORKDIR /app

COPY internal/test/integration/components/nodemultiproc/package*.json ./
RUN npm install

COPY internal/test/integration/components/nodemultiproc/service.js .
COPY internal/test/integration/components/nodemultiproc/start-all.js .

EXPOSE 5000 5001 5002 5003

CMD [ "node", "start-all.js" ]
