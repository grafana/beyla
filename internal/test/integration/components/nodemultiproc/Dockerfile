FROM node:20-slim@sha256:cba1d7bb8433bb920725193cd7d95d09688fb110b170406f7d4de948562f9850

WORKDIR /app

COPY internal/test/integration/components/nodemultiproc/package*.json ./
RUN npm install

COPY internal/test/integration/components/nodemultiproc/service.js .
COPY internal/test/integration/components/nodemultiproc/start-all.js .

EXPOSE 5000 5001 5002 5003

CMD [ "node", "start-all.js" ]

