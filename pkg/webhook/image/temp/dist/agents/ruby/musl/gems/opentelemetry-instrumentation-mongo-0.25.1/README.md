# OpenTelemetry Mongo Instrumentation

The OpenTelemetry Mongo Ruby gem is a community maintained instrumentation for [Mongo][mongo-home].

> [!NOTE]
>
> **Development Frozen:**
>
> Mongo Ruby Driver 2.23.0+ includes native OpenTelemetry instrumentation. For the best experience and continued support, we recommend:
>
> - **Mongo Ruby Driver < 2.23.0**: Use `opentelemetry-instrumentation-mongo` gem
> - **Mongo Ruby Driver ≥ 2.23.0**: Use Mongo Ruby Driver's built-in OpenTelemetry support (remove `opentelemetry-instrumentation-mongo` gem)
>
> Community instrumentation is compatible with Mongo Ruby Driver versions up to 2.23.x. Development of this gem is frozen for newer Mongo Ruby Driver versions in favor of the native integration.

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-mongo
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-mongo` in your `Gemfile`.

## Usage

To install the instrumentation, call `use` with the name of the instrumentation.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::Mongo'
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
  c.use 'OpenTelemetry::Instrumentation::Mongo', {
    # Sets how db_statement appears in your traces. The options are:
    # :obfuscate - (default) query parameters are visible, but values are masked.
    # :include - query parameters and values are both fully visible.
    # :omit - db_statement is omitted entirely.
    db_statement: :include,
  }
end
```

## Example

To run the example:

1. Start MongoDB using docker-compose
   - `docker-compose up mongo`
2. In a separate terminal window, `cd` to the examples directory and install gems
   - `cd example`
   - `bundle install`
3. Run the sample client script
   - `ruby mongo.rb`

This will run a few MongoDB commands, printing OpenTelemetry traces to the console as it goes.

## How can I get involved?

The `opentelemetry-instrumentation-mongo` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

Apache 2.0 license. See [LICENSE][license-github] for more information.

[mongo-home]: https://github.com/mongodb/mongo-ruby-driver
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
