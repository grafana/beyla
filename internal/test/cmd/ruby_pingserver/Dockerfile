# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest@sha256:6a1290331f4f9c5955515bb0135de54b45faccb3772b81b58d2b7bb450d759e7
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]