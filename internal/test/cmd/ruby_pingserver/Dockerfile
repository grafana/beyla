# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest@sha256:0f8b2bf616506a192bd8c151b4cb6b1e6beee6ff0792f1a1cb7c44d769807b79
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]