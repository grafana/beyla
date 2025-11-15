FROM postgres:latest@sha256:41bfa2e5b168fff0847a5286694a86cff102bdc4d59719869f6b117bb30b3a24
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data