# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest@sha256:4bef3ee023c0525189f1907ac256bc4511cc9ef4d5dc088c20b5c5a478638e28
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]