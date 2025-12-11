# Dockerfile that will build a container that runs a simple ruby http server on port 8080
FROM ruby:latest@sha256:b2dcadfcbaf93fceaf321b70c41a587ff535c2b10c22f8a25b401f21772670ba
EXPOSE 8080
COPY pingserver.rb /pingserver.rb
CMD ["ruby", "pingserver.rb"]