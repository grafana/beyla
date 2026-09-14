# OpenTelemetry Http Instrumentation

The HTTP instrumentation is a community-maintained instrumentation for the [HTTP][http-home] gem.

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-http
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-http` in your `Gemfile`.

## Usage

To use the instrumentation, call `use` with the name of the instrumentation:

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::HTTP'
end
```

Alternatively, you can also call `use_all` to install all the available instrumentation.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use_all
end
```

## Enriching http span names

We surface a hook to easily rename your span.

The lambda accepts as arguments (request_method, request_path) and returns a string that is set as the span name.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::Rack', { span_name_formatter: ->(request_method, request_path) { "HTTP #{request_method} #{request_path}" }
end
```

## Examples

Example usage can be seen in the [`./example/trace_demonstration.rb` file](https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/instrumentation/http/example/trace_demonstration.rb)

## How can I get involved?

The `opentelemetry-instrumentation-http` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-instrumentation-http` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[http-home]: https://github.com/httprb/http
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions

## HTTP semantic convention stability

This instrumentation by default emits the stable HTTP semantic conventions. The `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable can be used to opt-in to the old or duplicate (both old and stable) semantic conventions.

When setting the value for `OTEL_SEMCONV_STABILITY_OPT_IN`, you can specify which conventions you wish to adopt:

- `http` - Emits the stable HTTP and networking conventions.
- `http/dup` - **DEPRECATED: Will be removed on April 15, 2026.** Emits both the old and stable HTTP and networking conventions.
- `old` - **DEPRECATED: Will be removed on April 15, 2026.** Emits the old HTTP and networking conventions.

For additional information on migration, please refer to our [documentation](https://opentelemetry.io/docs/specs/semconv/non-normative/http-migration/).
