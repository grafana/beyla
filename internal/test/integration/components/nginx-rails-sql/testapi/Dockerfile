FROM ruby:3.4.8@sha256:90c7400d25f07962309fca2aa26b94bf1835e5bb7b30c7270e72463016f05f87 AS builder

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY . .

RUN apt-get update && apt-get install -y default-libmysqlclient-dev

# Install Rails 
RUN gem install rails
RUN gem install bundler rails
RUN bundle install

EXPOSE 3040

FROM ruby:3.4.8-slim@sha256:dcc535e858eeeac1f70eaf8c39ef7ee257b183a9e495cc5a9ef3e340eadf2d3d

RUN apt-get update && apt-get install -y default-libmysqlclient-dev

WORKDIR /
COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Run the app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
