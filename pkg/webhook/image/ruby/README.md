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

## Update the upstream distribution

The distribution is pinned by Git commit rather than a manually maintained version number.

1. Replace the commit SHA in `upstream-revision.txt`.
2. Regenerate `Gemfile.lock` with Docker:

   ```sh
   docker run --rm \
     --env HOST_UID="$(id -u)" \
     --env HOST_GID="$(id -g)" \
     --volume "$PWD:/work" \
     --workdir /work \
     ruby:3.3.12-slim-bookworm \
     sh -c '
       set -eu
       apt-get update
       apt-get install -y --no-install-recommends git
       rm -rf /var/lib/apt/lists/*
       gem install bundler --version 2.5.22 --no-document
       bundle _2.5.22_ lock --update
       bundle _2.5.22_ lock --add-platform \
         ruby \
         x86_64-linux-gnu \
         aarch64-linux-gnu \
         x86_64-linux-musl \
         aarch64-linux-musl
       chown "$HOST_UID:$HOST_GID" Gemfile.lock
     '
   ```

3. Review the upstream Ruby requirement, Rails minimum, and the requirements for dependencies listed in `DEPENDENCY_REQUIREMENTS`.
4. Update `beyla/compatibility.rb`, scanner checks, documentation, and tests if the supported versions intentionally change.
5. Run the unit tests and package-build validation commands from this README.

Do not edit the revision or dependency versions in `Gemfile.lock` manually. The package verifier checks that the revision, dependency graph, and installed gems agree.

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

## Run the package verifier directly

`verify_bundle.rb` requires an installed distribution tree, so first build and tag a packaging stage:

```sh
docker build \
  --target build-ruby-glibc \
  --tag beyla-ruby-verify \
  --file ../Dockerfile \
  ..
```

Then run the verifier against that tree:

```sh
docker run --rm \
  --volume "$PWD:/work:ro" \
  beyla-ruby-verify \
  ruby /work/verify_bundle.rb \
    /operator-build \
    /work/Gemfile.lock \
    /work/upstream-revision.txt
```

The Docker packaging stages already run this verifier automatically. A verification failure exits non-zero and stops the image build.
