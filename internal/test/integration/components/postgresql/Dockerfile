FROM postgres:latest@sha256:5ec39c188013123927f30a006987c6b0e20f3ef2b54b140dfa96dac6844d883f
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data