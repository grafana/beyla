# OpenTelemetry::SemanticConventions

The `opentelemetry-semantic_conventions` gem provides auto-generated constants
that represent the OpenTelemetry [Semantic Conventions][semantic-conventions].

## What is OpenTelemetry?

OpenTelemetry is an open source observability framework, providing a
general-purpose API, SDK, and related tools required for the instrumentation of
cloud-native software, frameworks, and libraries.

OpenTelemetry provides a single set of APIs, libraries, agents, and collector
services to capture distributed traces and metrics from your application. You
can analyze them using Prometheus, Jaeger, and other observability tools.

## How does this gem fit in?

The `opentelemetry-semantic_conventions` gem provides auto-generated constants
that represent the OpenTelemetry Semantic Conventions. They may be referenced
in instrumentation or end-user code in place of hard-coding the names of the
conventions. Because they are generated from the YAML models in the
specification, they are kept up-to-date for you.

## How do I get started?

Install the gem using:

```sh
gem install opentelemetry-semantic_conventions
```

Or, if you use Bundler, include `opentelemetry-semantic_conventions` in your
`Gemfile`.

## How do I use the gem?

The gem's versions match the corresponding
[OpenTelemetry Semantic Convention versions][semconv].

In version 1.36.0, we established a new pattern for naming the constants:

* `OpenTelemetry::SemConv::Incubating::#{CATEGORY_NAME}` is the prefix for
experimental, development, or deprecated constants
* `OpenTelemetry::SemConv::#{CATEGORY_NAME}` is the prefix for stable constants

Incubating constants will never be removed. If an incubating constant becomes
stable, it will be copied into the stable namespace and the value will be
available from two constants. The new constant's name will be the same, except
the `Incubating` namespace will be removed.

Prior to 1.36.0 (last version 1.11.0), constants follow a different naming
pattern: `OpenTelemetry::SemanticConventions::#{CATEGORY_NAME}`

These constants will be preserved to avoid breaking changes for users who rely
on the old constants. These constants do not differentiate between stable and
unstable constants. New constants will not be added to this namespace.

Require the gem once and reference any constant directly. Each namespace is
registered with Ruby's `autoload`, so the file backing a namespace is only loaded
the first time you reference one of its constants — you don't pay to load
conventions you never use.

```rb
require 'opentelemetry-semantic_conventions'

# Stable
OpenTelemetry::SemConv::HTTP::HTTP_REQUEST_METHOD            # => 'http.request.method'

# Incubating (experimental/deprecated)
OpenTelemetry::SemConv::Incubating::GEN_AI::GEN_AI_SYSTEM
```

If you want to require all of the 1.11.0 constants, you can use:

```rb
require 'opentelemetry/semantic_conventions'

# Use the constants however you feel necessary, eg:

puts "This is the value of #{OpenTelemetry::SemanticConventions::Trace::DB_USER}"
```

The constant names can be very long. You can consider aliasing the long bit in
another constant to save your fingertips some trouble.

```rb
SEMCONV_HTTP_INC = OpenTelemetry::SemConv::Incubating::HTTP

SEMCONV_HTTP_INC::HTTP_REQUEST_METHOD # which would return 'http.request.method'
```

## What's up with the gem's versions?

This gem doesn't follow semantic versioning. Instead, the version matches the
upstream [OpenTelemetry Semantic Conventions version][semconv].

## How do I rebuild the conventions?

To build the library against a new version of the semantic conventions, update SPEC_VERSION in the Rakefile, and then run `rake generate`.

Do not update the library's VERSION in version.rb.
That will be handled by the automation for releasing the gem.

## How can I get involved?

The `opentelemetry-semantic_conventions` gem source is on GitHub, along with
related gems.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry-Ruby special
interest group (SIG). You can get involved by joining us in
[GitHub Discussions][discussions-url] or attending our weekly meeting. See the
meeting calendar for dates and times. For more information on this and other
language SIGs, see the OpenTelemetry community page.

## License

The `opentelemetry-semantic_conventions` gem is distributed under the Apache 2.0
license. See LICENSE for more information.

[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
[semantic-conventions]: https://github.com/open-telemetry/semantic-conventions
[semconv]: https://opentelemetry.io/docs/specs/semconv/
