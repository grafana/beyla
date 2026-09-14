# OpenTelemetry ActionView Instrumentation

The ActionView instrumentation is a community-maintained instrumentation for the ActionView portion of the [Ruby on Rails][rails-home] web-application framework.

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-action_view
gem install opentelemetry-instrumentation-rails
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-action_view` in your `Gemfile`.

## Usage

To use the instrumentation, call `use` with the name of the instrumentation:

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::Rails'
  c.use 'OpenTelemetry::Instrumentation::ActionView'
end
```

Alternatively, you can also call `use_all` to install all the available instrumentation.

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use_all
end
```

## Configuration Options

The instrumentation supports the following configuration options:

- **disallowed_notification_payload_keys:** Specifies an array of keys that should be excluded from the notification payload as span attributes.
  - Default: `[]`
- **notification_payload_transform:** Specifies custom proc used to extract span attributes from the notification payload. Use this to rename keys, extract nested values, or perform any other custom logic.
  - Default: `nil`
- **legacy_span_names:** Specifies whether span names should use the legacy format where the subscription was reverse ordered and white space separated (e.g. `action_view render_template`). If set to `false`, the span name will match the name of the notification itself (e.g. `render_template.action_view`).
  - Default: `false`

## Active Support Instrumentation

This instrumentation relies entirely on `ActiveSupport::Notifications` and registers a custom Subscriber that listens to relevant events to report as spans.

See the table below for details of what [Rails Framework Hook Events](https://guides.rubyonrails.org/active_support_instrumentation.html#action-view) are recorded by this instrumentation:

| Event Name | Creates Span? | Notes |
| - | - | - |
| `render_template.action_view` | :white_check_mark: | Creates a span with kind `internal` |
| `render_partial.action_view` | :white_check_mark: | Creates a span with kind `internal` |
| `render_collection.action_view` | :white_check_mark: | Creates a span with kind `internal` |
| `render_layout.action_view` | :white_check_mark: | Creates a span with kind `internal` |

## Semantic Conventions

Internal spans are named using the name of the `ActiveSupport` event that was provided (e.g. `render_template.action_view`).

The following attributes may be recorded depending on the event type:

| Attribute Name | Type | Event(s) | Notes |
| - | - | - | - |
| `identifier` | String | All events | Full path to the template, partial, collection, or layout file |
| `layout` | String | `render_template.action_view` | Name of the layout being used (if applicable) |
| `count` | Integer | `render_collection.action_view` | Number of items in the collection |
| `cache_hits` | Integer | `render_collection.action_view` | Number of partials fetched from cache (only included when `cached: true`) |

> **Note:** The `locals` hash from the event payloads is not collected as an attribute because complex types like hashes are not supported by the OpenTelemetry specification v1.10.0. Only primitive types (String, Boolean, Numeric) and arrays of primitives are valid attribute values.

## Examples

Example usage can be seen in the [`./example/trace_request_demonstration.ru` file](https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/instrumentation/action_view/example/trace_request_demonstration.ru)

## Known issues

ActionView instrumentation uses ActiveSupport notifications and in the case when a subscriber raises in start method an unclosed span would break successive spans ends. Example:

```ruby
class CrashingStartSubscriber
  def start(name, id, payload)
    raise 'boom'
  end

  def finish(name, id, payload) end
end

::ActiveSupport::Notifications.subscribe('render_template.action_view', CrashingStartSubscriber.new)
```

## How can I get involved?

The `opentelemetry-instrumentation-action_view` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-instrumentation-action_view` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[rails-home]: https://github.com/rails/rails
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
