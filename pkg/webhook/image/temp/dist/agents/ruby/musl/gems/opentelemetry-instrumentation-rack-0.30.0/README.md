# OpenTelemetry Rack Instrumentation

The Rack instrumentation is a community-maintained instrumentation for the [Rack][rack-home] web server interface.

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-rack
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-rack` in your `Gemfile`.

### Version Compatibility

Older versions of Rack are not supported by the latest version of this instrumentation. If you are using an older version of Rack and need an earlier version of this instrumentation, then consider installing and pinning the compatible gem version, e.g.:

```console
gem opentelemetry-instrumentation-rack, "<version>"
```

| Rack Version | Instrumentation Version |
| ------------ | ----------------------- |
| `< 2.0`      | `= 0.22.1`              |
| `>= 2.0`     | `~> 0.23`               |

## Usage

To use the instrumentation, call `use` with the name of the instrumentation:

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::Rack'
end
```

Alternatively, you can also call `use_all` to install all the available instrumentation.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use_all
end
```

## Rack Middleware vs Rack Events

Since `v0.24.0`, this instrumentation uses `Rack::Events` as opposed to `Middleware` to support Requests that use Buffered Response Bodies.

If your application does not support `Rack::Events`, you may disable it by setting `use_rack_events: false`, e.g.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::Rack', use_rack_events: false
end
```

This will switch to using `Rack::Middleware` by default in dependent instrumentations.

See [#342](https://github.com/open-telemetry/opentelemetry-ruby-contrib/pull/342) for more details.

## Controlling span name cardinality

By default we will set the rack span name to match the format "HTTP #{method}" (ie. HTTP GET). There are different ways to control span names with this instrumentation.

### Enriching rack spans

We surface a hook to easily retrieve the rack span within the context of a request so that you can add information to or rename your server span.

This is how the rails controller instrumentation is able to rename the span names to match the controller and action that process the request. See <https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/opentelemetry-instrumentation-action_pack/v0.9.0/instrumentation/action_pack/lib/opentelemetry/instrumentation/action_pack/handlers/action_controller.rb#L29> for an example.

### High cardinality example

You can pass in a url quantization lambda that simply uses the URL path; the result is you will end up with high cardinality span names. However, this may be acceptable in your deployment and is easily configurable using the following example.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::Rack', { url_quantization: ->(path, _env) { path.to_s } }
end
```

## Examples

Example usage can be seen in the [`./example/trace_demonstration.rb` file](https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/instrumentation/rack/example/trace_demonstration.rb)

## How can I get involved?

The `opentelemetry-instrumentation-rack` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-instrumentation-rack` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[rack-home]: https://github.com/rack/rack
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
