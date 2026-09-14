# OpenTelemetry Grape Instrumentation

The Grape instrumentation is a community-maintained instrumentation for [Grape][grape], a REST-like API framework for Ruby.

It relies on the [Grape built-in support for `ActiveSupport::Notifications`](https://github.com/ruby-grape/grape#active-support-instrumentation) and the [OpenTelemetry Rack instrumentation](https://github.com/open-telemetry/opentelemetry-ruby-contrib/tree/opentelemetry-instrumentation-rack/v0.24.6/instrumentation/rack).

It currently supports the following events:

- `endpoint_run.grape`
- `endpoint_render.grape`
- `endpoint_run_filters.grape`
- `format_response.grape`

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-grape
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-grape` in your `Gemfile`.

## Usage

To use the instrumentation, call `use` with the name of the instrumentation:

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::Grape'
end
```

Grape is "designed to run on Rack or complement existing web application frameworks such as Rails and Sinatra". As a result, this instrumentation uses the Rack instrumentation and modifies the Rack spans, modifying the span name and adding Grape attributes and events. It is recommended to use it along with Rails and/or Sinatra instrumentations, if any of these frameworks are being used.

Alternatively, you can also call `use_all` to install all the available instrumentation.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use_all
end
```

### Configuration options

#### `:ignored_events` (array)

Indicate if any events should not produce spans.

- Accepted values: `:endpoint_render`, `:endpoint_run_filters`, `:format_response`.
- Defaults to `[]` (no ignored events).

Example:

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::Grape', { ignored_events: [:endpoint_run_filters] }
end
```

Note that the `endpoint_run` event cannot be ignored. If you need to disable the instrumentation, set `:enabled` to `false`:

```ruby
OpenTelemetry::SDK.configure do |c|
  config = { 'OpenTelemetry::Instrumentation::Grape' => { enabled: false } }
  c.use_all(config)
end
```

## Examples

Example usage can be seen in the [`./example/trace_demonstration.rb` file](https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/instrumentation/grape/example/trace_demonstration.rb)

## How can I get involved?

The `opentelemetry-instrumentation-grape` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## HTTP semantic convention stability

Grape instrumentation installs Rack middleware which by default emits the stable HTTP semantic conventions. The `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable can be used to opt-in to the old or duplicate (both old and stable) semantic conventions.

When setting the value for `OTEL_SEMCONV_STABILITY_OPT_IN`, you can specify which conventions you wish to adopt:

- `http` - Emits the stable HTTP and networking conventions.
- `http/dup` - **DEPRECATED: Will be removed on April 15, 2026.** Emits both the old and stable HTTP and networking conventions.
- `old` - **DEPRECATED: Will be removed on April 15, 2026.** Emits the old HTTP and networking conventions.

For additional information on migration, please refer to our [documentation](https://opentelemetry.io/docs/specs/semconv/non-normative/http-migration/).

## License

The `opentelemetry-instrumentation-grape` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
[grape]: https://github.com/ruby-grape/grape
