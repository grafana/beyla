FROM postgres:latest@sha256:bfe50b2b0ddd9b55eadedd066fe24c7c6fe06626185b73358c480ea37868024d
ENV POSTGRES_DB sqltest
COPY accounting.sql /docker-entrypoint-initdb.d/
EXPOSE 5432
# Run me with: docker run -p 5432:5432 -e POSTGRES_PASSWORD=postgres <image name>
# Password is needed on start, so that we can inject the schema and data
