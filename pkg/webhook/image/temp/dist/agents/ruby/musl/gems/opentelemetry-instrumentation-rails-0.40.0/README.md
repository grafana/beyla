# OpenTelemetry Rails Instrumentation

The Rails instrumentation is a community-maintained instrumentation for the [Ruby on Rails][rails-home] web-application framework.

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-rails
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-rails` in your `Gemfile`.

### Version Compatibility

EOL versions of Rails are not supported by the latest version of this instrumentation. If you are using an EOL version of Rails and need an earlier version of this instrumentation, then consider installing and pinning the compatible gem version, e.g.:

```console
gem opentelemetry-instrumentation-rails, "<version>"
```

| Rails Version | Instrumentation Version |
| --- | --- |
| `5.2` | `= 0.24.1` |
| `6.0` | `= 0.28.0` |
| `6.1` | `= 0.34` |
| `7.x` | `~> 0.34` |

## Usage

### Recommended

To use the Rails instrumentation, call `use_all` so it installs all the instrumentation gems.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use_all
end
```

### Experimental

There is also an experimental Railtie available that will bootstrap the SDK:

```ruby
# Gemfile

gem "opentelemetry-instrumentation-rails", require: "opentelemetry/instrumentation/rails/railtie"

```

### Configuration options

The Rails instrumentation attempts to mirror the structure of the Ruby on Rails. It is a collection of instrumentation gems for components of Rails such as Action View, Active Record, Action Pack, etc...

You may want to include all of the Rails instrumentation but disable a single instrumentation gem that it includes. Here is an example of how you can disable Active Record when using this instrumentation gem.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use_all({ 'OpenTelemetry::Instrumentation::ActiveRecord' => { enabled: false } })
end
```

## Examples

Example usage can be seen in the [`./example/trace_demonstration.rb` file](https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/instrumentation/rails/example/trace_request_demonstration.ru)

## How can I get involved?

The `opentelemetry-instrumentation-rails` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## HTTP semantic convention stability

Rails instrumentation installs Rack middleware which by default emits the stable HTTP semantic conventions. The `OTEL_SEMCONV_STABILITY_OPT_IN` environment variable can be used to opt-in to the old or duplicate (both old and stable) semantic conventions.

When setting the value for `OTEL_SEMCONV_STABILITY_OPT_IN`, you can specify which conventions you wish to adopt:

- `http` - Emits the stable HTTP and networking conventions.
- `http/dup` - **DEPRECATED: Will be removed on April 15, 2026.** Emits both the old and stable HTTP and networking conventions.
- `old` - **DEPRECATED: Will be removed on April 15, 2026.** Emits the old HTTP and networking conventions.

For additional information on migration, please refer to our [documentation](https://opentelemetry.io/docs/specs/semconv/non-normative/http-migration/).

## License

The `opentelemetry-instrumentation-rails` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[rails-home]: https://github.com/rails/rails
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
