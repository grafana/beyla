FROM postgres:latest@sha256:1ffc019dae94eca6b09a49ca67d37398951346de3c3d0cfe23d8d4ca33da83fb
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data