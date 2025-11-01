FROM postgres:latest@sha256:7499fa0ed6b106d3b513fe792d673f1b496a539a541674fdcd9539c13c6427f3
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data