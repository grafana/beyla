FROM ruby:3.4.8@sha256:ee8d45137f70f47213ae33998cf79bd7cb7209291a912632f039c81ab28ae7fb AS builder

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

FROM ruby:3.4.8-slim@sha256:3370b8734f2af794a636614925378ca475699da8459e0394d86c66ec715e4268

RUN apt-get update && apt-get install -y default-libmysqlclient-dev

WORKDIR /
COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Run the app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
