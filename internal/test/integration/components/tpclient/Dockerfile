FROM node:20-slim@sha256:6c51af7dc83f4708aaac35991306bca8f478351cfd2bda35750a62d7efcf05bb

WORKDIR /app

COPY internal/test/integration/components/tpclient/package*.json ./
RUN npm install

COPY internal/test/integration/components/tpclient/service.js ./
COPY internal/test/integration/components/tpclient/start-all.js ./

EXPOSE 6000 6001 6002

CMD ["node", "start-all.js"]
