# OpenTelemetry Active Model Serializers Instrumentation

The OpenTelemetry Active Model Serializers gem is a community maintained instrumentation for [Active Model Serializers][active_model_serializers-home].

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-active_model_serializers
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-active_model_serializers` in your `Gemfile`.

## Usage

To install the instrumentation, call `use` with the name of the instrumentation.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::ActiveModelSerializers'
end
```

Alternatively, you can also call `use_all` to install all the available instrumentation.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use_all
end
```

## Examples

Example usage of active_model_serializers can be seen [in the `./example/` folder](https://github.com/open-telemetry/opentelemetry-ruby-contrib/tree/main/instrumentation/active_model_serializers/example)

## How can I get involved?

The `opentelemetry-instrumentation-active_model_serializers` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

Apache 2.0 license. See [LICENSE][license-github] for more information.

[active_model_serializers-home]: https://github.com/rails-api/active_model_serializers
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
