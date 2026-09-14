# OpenTelemetry Racecar Instrumentation

The Racecar instrumentation is a community-maintained instrumentation for [Racecar](https://github.com/zendesk/racecar), a client library for Apache Kafka.

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-racecar
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-racecar` in your `Gemfile`.

## Runtime requirements

This instrumentation is built on top of Racecar's integration with `ActiveSupport::Notifications`. `ActiveSupport::Notification` will need to be loaded before the instrumentation is installed (as below) or the installation will cancel.

## Usage

To use the instrumentation, call `use` with the name of the instrumentation:

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::Racecar'
end
```

Alternatively, you can also call `use_all` to install all the available instrumentation.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use_all
end
```

## Examples

Example usage can be seen in the [`./example` directory](https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/instrumentation/racecar/example). Run `./trace_demonstration.sh` to see its behaviour.

## How can I get involved?

The `opentelemetry-instrumentation-racecar` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-instrumentation-racecar` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
