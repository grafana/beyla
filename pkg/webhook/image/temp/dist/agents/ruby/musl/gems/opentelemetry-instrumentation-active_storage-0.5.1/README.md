# OpenTelemetry ActiveStorage Instrumentation

The ActiveStorage instrumentation is a community-maintained instrumentation for the ActiveStorage portion of the [Ruby on Rails][rails-home] web-application framework.

## How do I get started?

Install the gem using:

```bash
# Install just the ActiveStorage instrumentation
gem install opentelemetry-instrumentation-active_storage
# Install the ActiveStorage instrumentation along with the rest of the Rails-related instrumentation
gem install opentelemetry-instrumentation-rails
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-active_storage` in your `Gemfile`.

## Usage

To use the instrumentation, call `use` with the name of the instrumentation:

```ruby
OpenTelemetry::SDK.configure do |c|
  # Use only the ActiveStorage instrumentation
  c.use 'OpenTelemetry::Instrumentation::ActiveStorage'
  # Use the ActiveStorage instrumentation along with the rest of the Rails-related instrumentation
  c.use 'OpenTelemetry::Instrumentation::Rails'
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

- **`disallowed_notification_payload_keys`:** Array of keys excluded from notification payloads before they are recorded as span attributes. Keys are matched against the payload after the `active_storage.` prefix has been applied (e.g. `active_storage.url`).
  - Default: `[]`
- **`notification_payload_transform`:** Custom `proc` used to extract span attributes from notification payloads. The proc receives the payload after the built-in `active_storage.` prefix transform and must return a `Hash`. Use this to rename keys, extract nested values, or perform any other custom logic.
  - Default: `nil`
- **`key`:** Whether to include the secure token (`active_storage.key`) as a span attribute. Valid values are `:omit` and `:include`. When set to `:omit`, the key is appended to `disallowed_notification_payload_keys`.
  - Default: `:omit`
- **`url`:** Whether to include the URL (`active_storage.url`) as a span attribute. Valid values are `:omit` and `:include`. When set to `:omit`, the key is appended to `disallowed_notification_payload_keys`.
  - Default: `:omit`

Example with all options set:

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::ActiveStorage', {
    disallowed_notification_payload_keys: ['active_storage.checksum'],
    notification_payload_transform: ->(payload) { payload },
    key: :include,
    url: :include,
  }
end
```

## Active Support Instrumentation

This instrumentation relies entirely on `ActiveSupport::Notifications` and registers a custom Subscriber that listens to relevant events to report as spans.

See the table below for details of what [Rails Framework Hook Events](https://guides.rubyonrails.org/active_support_instrumentation.html#active-storage) are recorded by this instrumentation:

| Event Name | Creates Span? | Notes |
| - | - | - |
| `preview.active_storage` | :white_check_mark: | Creates an `internal` span |
| `transform.active_storage` | :white_check_mark: | Creates an `internal` span |
| `analyze.active_storage` | :white_check_mark: | Creates an `internal` span |
| `service_upload.active_storage` | :white_check_mark: | Creates an `internal` span |
| `service_streaming_download.active_storage` | :white_check_mark: | Creates an `internal` span |
| `service_download_chunk.active_storage` | :white_check_mark: | Creates an `internal` span |
| `service_download.active_storage` | :white_check_mark: | Creates an `internal` span |
| `service_delete.active_storage` | :white_check_mark: | Creates an `internal` span |
| `service_delete_prefixed.active_storage` | :white_check_mark: | Creates an `internal` span |
| `service_exist.active_storage` | :white_check_mark: | Creates an `internal` span |
| `service_url.active_storage` | :white_check_mark: | Creates an `internal` span |
| `service_update_metadata.active_storage` | :white_check_mark: | Creates an `internal` span |

### Options

ActiveStorage instrumentation doesn't expose secure tokens and urls by default, but if they are needed, simply use `:key` and `:url` option:

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::ActiveStorage', { key: :include, url: :include }
end
```

## Semantic Conventions

Internal spans are named using the name of the `ActiveSupport` event that was provided (e.g. `service_upload.active_storage`).

Attributes attached to each event payload are prefixed with `active_storage.` (e.g. `active_storage.checksum`).

## Examples

Example usage can be seen in the [`./example/trace_demonstration.rb` file](https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/instrumentation/active_storage/example/trace_demonstration.rb)

## How can I get involved?

The `opentelemetry-instrumentation-active_storage` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-instrumentation-active_storage` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[rails-home]: https://github.com/rails/rails
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
