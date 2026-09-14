# OpenTelemetry Dalli Instrumentation

The OpenTelemetry Dalli gem is a community maintained instrumentation for the [Dalli][dalli-home] Memcache client.

## Dalli 4.2.0+ Native Integration

Dalli 4.2.0+ includes native OpenTelemetry instrumentation. For the best experience and continued support, we recommend:

- **Dalli < 4.2.0**: Use `opentelemetry-instrumentation-dalli` gem
- **Dalli ≥ 4.2.0**: Use Dalli's built-in OpenTelemetry support (remove `opentelemetry-instrumentation-dalli` gem)

Community instrumentation is compatible with Dalli versions up to 4.1.x. Development of this gem is frozen for newer Dalli versions in favor of the native integration.

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-dalli
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-dalli` in your `Gemfile`.

## Usage

To install the instrumentation, call `use` with the name of the instrumentation.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::Dalli'
end
```

Alternatively, you can also call `use_all` to install all the available instrumentation.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use_all
end
```

### Configuration options

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::Dalli', {
    # You may optionally set a value for 'peer.service', which
    # will be included on all spans from this instrumentation:
    peer_service: '',

    # The obfuscation of query in the db.statement attribute is enabled by default.
    # To disable, set db_statement to :include; to omit the query completely, set db_statement to :omit
    db_statement: :include,
  }
end
```

## How can I get involved?

The `opentelemetry-instrumentation-dalli` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

Apache 2.0 license. See [LICENSE][license-github] for more information.

[dalli-home]: https://github.com/petergoldstein/dalli
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
