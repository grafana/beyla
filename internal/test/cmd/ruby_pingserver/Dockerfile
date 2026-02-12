# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest@sha256:36ec449d363dbe7ddb7784a12934a01880fd3a86f6bf059dc1f87f0d83afc953
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]