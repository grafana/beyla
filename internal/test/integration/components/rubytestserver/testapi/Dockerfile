FROM ruby:3.4.8@sha256:95b22f0745feddf4f3e749840c2b41b568efa30234d6eca4537c1dd042850415 AS builder

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY internal/test/integration/components/rubytestserver/testapi .

# Install Rails 
RUN gem install rails
RUN gem install bundler
RUN bundle install
RUN bundle exec rake app:update:bin
RUN bin/rails db:migrate

EXPOSE 3040

FROM ruby:3.4.8-slim@sha256:d77fc2809d1e9b461bdd305694b6d69f036b477b9ab6f69cd677d88aede2f1eb

WORKDIR /
COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Run the node app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
