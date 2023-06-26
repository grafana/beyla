FROM ruby:3.0.2

# Set the working directory to /build
WORKDIR /build

# Copy the source code into the image for building
COPY test/ test/

WORKDIR /build/test/integration/components/rubytestserver/testapi

# Install NodeJS express
RUN gem install rails
RUN gem install bundler rails
RUN bundle install

EXPOSE 3040

# Run the node app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
