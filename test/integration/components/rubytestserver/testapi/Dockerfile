FROM ruby:3.0.2 as builder

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY test/integration/components/rubytestserver/testapi .

# Install Rails 
RUN gem install rails
RUN gem install bundler rails
RUN bundle install

EXPOSE 3040

FROM ruby:3.0.2-slim

WORKDIR /
COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Run the node app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
