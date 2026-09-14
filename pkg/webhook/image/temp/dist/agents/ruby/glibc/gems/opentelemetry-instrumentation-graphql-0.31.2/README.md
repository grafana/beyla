# OpenTelemetry GraphQL Instrumentation

The OpenTelemetry GraphQL Ruby gem is a community maintained instrumentation for [GraphQL][graphql-home]. The GraphQL integration activates instrumentation for GraphQL queries.

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-graphql
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-graphql` in your `Gemfile`.

## Usage

To use the instrumentation, call `use` with the name of the instrumentation:

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::GraphQL'
end
```

### Configuration options

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::GraphQL', {
    # If this option is not provided the default behaviour is to instrument all
    # schemas that extend GraphQL::Schema
    schemas: [MyAppSchema],

    # The following options are disabled by default as they generate
    # large traces, but can be enabled using the following keys to add
    # spans that provide more detail.
    # Further details about what these keys correspond can be found on the [platform_tracing.rb class](https://github.com/rmosolgo/graphql-ruby/blob/1.10.x/lib/graphql/tracing/platform_tracing.rb#L28-L73).
    # enable_platform_field maps to the execute_field and execute_field_lazy keys
    enable_platform_field: false,
    # enable_platform_authorized maps to the authorized and authorized_lazy keys
    enable_platform_authorized: false,
    # enable_platform_resolve_type maps to the resolve_type and resolve_type_lazy keys
    enable_platform_resolve_type: false,

    # Controls if platform tracing (field/authorized/resolve_type)
    # should use the legacy span names (e.g. "MyType.myField") or the
    # new normalized span names (e.g. "graphql.execute_field").
    legacy_platform_span_names: false
  }
end
```

Alternatively, you can also call `use_all` to install all the available instrumentation.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use_all
end
```

## Examples

An example of usage can be seen in [`example/graphql.rb`](https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/instrumentation/graphql/example/graphql.rb).

## How can I get involved?

The `opentelemetry-instrumentation-graphql` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-instrumentation-graphql` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[graphql-home]: https://github.com/rmosolgo/graphql-ruby
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
