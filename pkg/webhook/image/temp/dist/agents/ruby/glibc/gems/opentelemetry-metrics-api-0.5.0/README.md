# opentelemetry-metrics-api

The `opentelemetry-metrics-api` gem is an alpha implementation of the [OpenTelemetry Metrics API][metrics-api] for Ruby applications. Using `opentelemetry-metrics-api`, a library or application can code against the OpenTelemetry interfaces to produce metric data.

## What is OpenTelemetry?

[OpenTelemetry][opentelemetry-home] is an open source observability framework, providing a general-purpose API, SDK, and related tools required for the instrumentation of cloud-native software, frameworks, and libraries.

OpenTelemetry provides a single set of APIs, libraries, agents, and collector services to capture distributed traces and metrics from your application. You can analyze them using Prometheus, Jaeger, and other observability tools.

## How does this gem fit in?

The `opentelemetry-metrics-api` gem defines the core OpenTelemetry interfaces in the form of abstract classes and no-op implementations. That is, it defines interfaces and data types sufficient for a library or application to code against to produce telemetry data, but does not actually collect, analyze, or export the data.

To collect and analyze telemetry data, _applications_ should also
install a concrete implementation of the API, such as the
`opentelemetry-metrics-sdk` gem. However, _libraries_ that produce
telemetry data should depend only on `opentelemetry-metrics-api`,
deferring the choice of concrete implementation to the application developer.

This code is still under development and is not a complete implementation of the Metrics API. Until the code becomes stable, Metrics API functionality will live outside the `opentelemetry-api` library.

## How do I get started?

Install the gem using:

```sh
gem install opentelemetry-metrics-api
```

Or, if you use [bundler][bundler-home], include `opentelemetry-metrics-api` in your `Gemfile`.

Then, use the OpenTelemetry interfaces to produces traces and other telemetry data. Following is a basic example.

```ruby
require 'opentelemetry-metrics-api'

# Obtain the current default meter provider
provider = OpenTelemetry.meter_provider

# Create a meter
meter = provider.meter('my_app', '1.0')

# Record a metric
histogram = meter.create_histogram('histogram', unit: 's', description: 'duration in seconds')

# Record a metric.
histogram.record(123, attributes: {'foo' => 'bar'})
```

For additional examples, see the [examples on github][examples-github].

## How can I get involved?

The `opentelemetry-metrics-api` gem source is [on github][repo-github], along with related gems including `opentelemetry-metrics-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry-Ruby special interest group (SIG). You can get involved by joining us in [GitHub Discussions][discussions-url] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

There's still work to be done, to get to a spec-compliant metrics implementation and we'd love to have more folks contributing to the project. Check the [repo][repo-github] for issues and PRs labeled with `metrics` to see what's available.

## Feedback

During this experimental stage, we're looking for lots of community feedback about this gem. Please add your comments to Issue [#1662][1662].

## License

The `opentelemetry-api` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[metrics-api]: https://opentelemetry.io/docs/specs/otel/metrics/api/
[opentelemetry-home]: https://opentelemetry.io
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby/blob/main/LICENSE
[examples-github]: https://github.com/open-telemetry/opentelemetry-ruby/tree/main/examples
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
[1662]: https://github.com/open-telemetry/opentelemetry-ruby/issues/1662
