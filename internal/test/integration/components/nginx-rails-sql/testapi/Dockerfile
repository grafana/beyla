FROM ruby:3.4.8@sha256:40b615a7ae6859d6ff82cc389e9b1ea673f2683a035da2c48e1ef203f7c1fe52 AS builder

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

FROM ruby:3.4.8-slim@sha256:82081a00d5e1c2e3df6ae927d3ecc13292ded57a820c33a1c7d00cca30356d5d

RUN apt-get update && apt-get install -y default-libmysqlclient-dev

WORKDIR /
COPY --from=builder /build .
COPY --from=builder /usr/local/bundle /usr/local/bundle

# Run the app
CMD [ "rails", "server", "-p", "3040", "-b", "0.0.0.0" ]
