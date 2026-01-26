# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest@sha256:299b7872d1d2f9e73666ef82ea1d759f1976a8bd16367e8637e3665ff94e942d
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]