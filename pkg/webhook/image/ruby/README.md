# Ruby distribution development

## Requirements

The recommended test environment requires:

- Linux
- Docker with access to the Docker daemon

To run the tests directly on the host, install:

- CRuby 3.3 or newer
- RubyGems
- Bundler
- Minitest

Check the local installation:

```sh
ruby --version
bundle --version
ruby -rminitest -e 'puts Minitest::VERSION'
```

If Bundler or Minitest is missing:

```sh
gem install bundler minitest
```

The unit tests do not require `bundle install`. The committed `Gemfile.lock` describes the packaged distribution, not the test environment.

## Run with Docker

From this directory:

```sh
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --volume "$PWD:/work" \
  --workdir /work \
  ruby:3.3.12-slim-bookworm \
  ruby -I. -Itest -e 'Dir["test/test_*.rb"].sort.each { |file| require_relative file }'
```

Docker downloads the Ruby image on the first run. No host Ruby installation is needed.

## Run with local Ruby

From this directory:

```sh
ruby -I. -Itest -e 'Dir["test/test_*.rb"].sort.each { |file| require_relative file }'
```

The command exits non-zero when a test fails.

## Validate package builds

These commands validate packaging; they are not runtime or injector end-to-end tests. Run them from this directory:

```sh
docker build \
  --target build-ruby-glibc \
  --output type=cacheonly \
  --file ../Dockerfile \
  ..

docker build \
  --target build-ruby-musl \
  --output type=cacheonly \
  --file ../Dockerfile \
  ..
```

The builds require network access to GitHub, RubyGems, and the configured container registries.
