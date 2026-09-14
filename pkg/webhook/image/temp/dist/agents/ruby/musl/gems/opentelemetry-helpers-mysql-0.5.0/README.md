# OpenTelemetry Instrumentation Helpers: MySQL

This Ruby gem contains logic shared among MySQL adapter libraries, such as mysql2 and trilogy. It's intended for use by gem authors instrumenting MySQL adapter libraries.

## Usage

Add the gem to your instrumentation's gemspec file:

```ruby
# opentelemetry-instrumentation-your-gem.gemspec
  spec.add_dependency 'opentelemetry-helpers-mysql'
```

Add the gem to your instrumentation's Gemfile:

```ruby
# Gemfile

group :test do
  gem 'opentelemetry-helpers-mysql', path: '../../helpers/mysql'
end
```

Make sure the `Instrumentation` class for your gem contains configuration options for:

- `:span_name`: The type of span name desired for the trace.
  Example: `option :span_name, default: :statement_type, validate: %I[statement_type db_name db_operation_and_name]`

## Examples

To set the span name in your library:

```ruby
tracer.in_span(
  OpenTelemetry::Helpers::MySQL.database_span_name(sql, operation, database_name, config),
  attributes: attributes.merge!(OpenTelemetry::Instrumentation::Mysql2.attributes),
  kind: :client
) do
  super(sql, options)
end
```

## How can I get involved?

The `opentelemetry-helpers-mysql` gem source is [on github][repo-github], along with related gems including `opentelemetry-instrumentation-mysql2` and `opentelemetry-instrumentation-trilogy`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-helpers-mysql` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
