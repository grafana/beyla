# OpenTelemetry ActionMailer Instrumentation

The ActionMailer instrumentation is a community-maintained instrumentation for the ActionMailer portion of the [Ruby on Rails][rails-home] web-application framework.

## How do I get started?

Install the gem using:

```bash
# Install just the ActionMailer instrumentation
gem install opentelemetry-instrumentation-action_mailer
# Install the ActionMailer instrumentation along with the rest of the Rails-related instrumentation
gem install opentelemetry-instrumentation-rails
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-action_mailer` in your `Gemfile`.

## Usage

To use the instrumentation, call `use` with the name of the instrumentation:

```ruby
OpenTelemetry::SDK.configure do |c|
  # Use only the ActionMailer instrumentation
  c.use 'OpenTelemetry::Instrumentation::ActionMailer'
  # Use the ActionMailer instrumentation along with the rest of the Rails-related instrumentation
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

- **`disallowed_notification_payload_keys`:** Array of keys excluded from the `deliver.action_mailer` notification payload before they are recorded as span attributes. Keys are matched against the payload after the ECS-style transform documented under [Semantic Conventions](#semantic-conventions), so use the transformed names (e.g. `email.to.address`).
  - Default: `[]`
- **`disallowed_process_payload_keys`:** Array of keys excluded from the `process.action_mailer` notification payload before they are recorded as span attributes.
  - Default: `[]`
- **`notification_payload_transform`:** Custom `proc` used to extract span attributes from the `deliver.action_mailer` notification payload. The proc receives the payload after the built-in ECS-style transform has been applied and must return a `Hash`. Use this to rename keys, extract nested values, or perform any other custom logic.
  - Default: `nil`
- **`process_payload_transform`:** Custom `proc` used to extract span attributes from the `process.action_mailer` notification payload. Must return a `Hash`.
  - Default: `nil`
- **`email_address`:** Whether to include email addresses (`email.to.address`, `email.from.address`, `email.cc.address`, `email.bcc.address`) as span attributes. Valid values are `:omit` and `:include`. When set to `:omit`, these keys are appended to `disallowed_notification_payload_keys`.
  - Default: `:omit`

Example with all options set:

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::ActionMailer', {
    disallowed_notification_payload_keys: ['email.subject'],
    disallowed_process_payload_keys: ['args'],
    notification_payload_transform: ->(payload) { payload.merge('email.tenant' => payload['email.x_mailer']) },
    process_payload_transform: ->(payload) { payload },
    email_address: :include,
  }
end
```

## Active Support Instrumentation

This instrumentation relies entirely on `ActiveSupport::Notifications` and registers a custom Subscriber that listens to relevant events to report as spans.

See the table below for details of what [Rails Framework Hook Events](https://guides.rubyonrails.org/active_support_instrumentation.html#action-mailer) are recorded by this instrumentation:

| Event Name | Creates Span? | Notes |
| - | - | - |
| `deliver.action_mailer` | :white_check_mark: | Creates a span with kind `internal` and email content and status |
| `process.action_mailer` | :white_check_mark: | Creates a span with kind `internal` that will include email rendering spans |

### Options

ActionMailer instrumentation doesn't expose email addresses by default, but if email addresses are needed, simply use `:email_address` option:

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::ActionMailer', { email_address: :include }
end
```

If only want to hide certain attributes from the notifications payload for email address:

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::ActionMailer', { email_address: :include, disallowed_notification_payload_keys: ['email.to.address'] }
end
```

## Semantic Conventions

Internal spans are named using the name of the `ActiveSupport` event that was provided (e.g. `deliver.action_mailer`).

### Attributes attached to the `deliver.action_mailer` event payload

| Attribute Name | Type | Notes |
| - | - | - |
| `email.x_mailer` | String | Mailer class that is used to send mail |
| `email.message_id` | String | Set from Mail gem |
| `email.subject` | String | Mail subject |
| `email.to.address` | Array | Receiver for mail (omit by default, include when `email_address` set to `:include`) |
| `email.from.address` | Array | Sender for mail (omit by default, include when `email_address` set to `:include`) |
| `email.cc.address` | Array | mail CC (omit by default, include when `email_address` set to `:include`) |
| `email.bcc.address` | Array | mail BCC (omit by default, include when `email_address` set to `:include`) |

### Attributes attached to the `process.action_mailer` event payload

| Attribute Name | Type | Notes |
| - | - | - |
| `mailer` | String | Mailer class that is used to render the mail |
| `action` | String | Method from the mailer class called to render the mail |
| `args` | Array | Arguments passed to the method to render the email |

## Examples

Example usage can be seen in the [`./example/trace_request_demonstration.ru` file](https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/instrumentation/action_mailer/example/trace_request_demonstration.ru)

## How can I get involved?

The `opentelemetry-instrumentation-action_mailer` gem source is [on GitHub][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-instrumentation-action_mailer` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[rails-home]: https://github.com/rails/rails
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
