# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]