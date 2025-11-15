# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest@sha256:88ce517a2537f1255e97d2b290b6460036dc7b19dfed751b2e6d140d1c1d14b5
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]