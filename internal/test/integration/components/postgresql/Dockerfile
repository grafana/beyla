FROM postgres:latest@sha256:0033c194dc640cc4dcc62ef7c3117e5791365cca5fc1a2998e5c1693254784bc
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data