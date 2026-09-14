# OpenTelemetry ActiveJob Instrumentation

The OpenTelemetry Active Job gem is a community maintained instrumentation for [ActiveJob][activejob-home].

## How do I get started?

Install the gem using:

```console
gem install opentelemetry-instrumentation-active_job
```

Or, if you use [bundler][bundler-home], include `opentelemetry-instrumentation-active_job` in your `Gemfile`.

## Usage

To use the instrumentation, call `use` with the name of the instrumentation:

```ruby
OpenTelemetry::SDK.configure do |c|
  c.use 'OpenTelemetry::Instrumentation::ActiveJob'
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

- **span_naming:** Determines how span names are generated.
  - `:job_class` – Span names are set to `<job class name> <operation>`.
  - `:queue` – Span names are set to `<queue name> <operation>`.
  - Default: `:queue`
- **force_flush:** If enabled, all completed spans are synchronously flushed at
  the end of each job execution. This is recommended for job systems that fork
  worker processes, such as Resque.
  - Default: `false`
- **propagation_style:** Controls how job execution traces are related to the
  trace where the job was enqueued.
  - `:link` – The job runs in a separate trace, with its initial span linked to
    the enqueuing span via a Span Link.
  - `:child` – The job runs in the same trace, as a direct child of the
    enqueuing span.
  - `:none` – No explicit link between the job execution and the enqueuing span.
  - Default: `:link`

## Active Support Instrumentation

Earlier versions of this instrumentation relied on registering custom `around_perform` hooks in order to deal with limitations
in `ActiveSupport::Notifications`, however those patches resulted in error reports and inconsistent behavior when combined with other gems.

This instrumentation now relies entirely on `ActiveSupport::Notifications` and registers a custom Subscriber that listens to relevant events to report as spans.

See the table below for details of what [Rails Framework Hook Events](https://guides.rubyonrails.org/active_support_instrumentation.html#active-job) are recorded by this instrumentation:

| Event Name | Creates Span? | Notes |
| - | - | - |
| `enqueue_at.active_job` | :white_check_mark: | Creates an egress span with kind `producer` |
| `enqueue.active_job` | :white_check_mark: | Creates an egress span with kind `producer` |
| `enqueue_retry.active_job` | :white_check_mark: | Creates an `internal` span |
| `perform_start.active_job` | :x: | This is invoked prior to the appropriate ingress point and is therefore ignored |
| `perform.active_job` | :white_check_mark: | Creates an ingress span with kind `consumer` |
| `retry_stopped.active_job` | :white_check_mark: | Creates and `internal` span with an `exception` event |
| `discard.active_job` | :white_check_mark: | Creates and `internal` span with an `exception` event |
| `step.active_job` | :white_check_mark: | Creates an `internal` span |

## Semantic Conventions

This instrumentation generally uses [Messaging semantic conventions](https://opentelemetry.io/docs/specs/semconv/messaging/messaging-spans/) by treating job enqueuers as `producers` and workers as `consumers`.

Internal spans are named using the name of the `ActiveSupport` event that was provided.

Attributes that are specific to this instrumentation are recorded under `messaging.active_job.*`:

| Attribute Name | Type | Notes |
| - | - | - |
| `code.namespace` | String | `ActiveJob` class name |
| `messaging.system` | String | Static value set to `active_job` |
| `messaging.destination` | String | Set from `ActiveJob#queue_name` |
| `messaging.message.id` | String | Set from `ActiveJob#job_id` |
| `messaging.active_job.adapter.name` | String | The name of the `ActiveJob` adapter implementation |
| `messaging.active_job.message.priority` | String | Present when set by the client from `ActiveJob#priority` |
| `messaging.active_job.message.provider_job_id` | String | Present if the underlying adapter has backend specific message ids |

For jobs including the `ActiveJob::Continuable` module, the following attributes are added to spans created for a `step`:

| `messaging.active_job.step.name` | String | Step name |
| `messaging.active_job.step.state` | String | Either `started` or `resumed` |
| `messaging.active_job.step.result` | String | Static value set to `interrupted` if the job was interrupted |
| `messaging.active_job.step.cursor` | String | The persisted value after calling `step.set!` or `step.advance!` |

## Differences between ActiveJob versions

### ActiveJob 6.1

`perform.active_job` events do not include timings for `ActiveJob` callbacks therefore time spent in `before` and `after` hooks will be missing

### ActiveJob 7+

`perform.active_job` no longer includes exceptions handled using `rescue_from` in the payload.

In order to preserve this behavior you will have to update the span yourself, e.g.

```ruby
  rescue_from MyCustomError do |e|
    # Custom code to handle the error
    span = OpenTelemetry::Instrumentation::ActiveJob.current_span
    span.record_exception(e)
    span.status = OpenTelemetry::Trace::Status.error('Job failed')
  end
```

## Examples

Example usage can be seen in the [`./example/active_job.rb` file](https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/instrumentation/active_job/example/active_job.rb)

## How can I get involved?

The `opentelemetry-instrumentation-active_job` gem source is [on github][repo-github], along with related gems including `opentelemetry-api` and `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us on our [GitHub Discussions][discussions-url], [Slack Channel][slack-channel] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-instrumentation-active_job` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[activejob-home]: https://guides.rubyonrails.org/active_job_basics.html
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby-contrib/blob/main/LICENSE
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[slack-channel]: https://cloud-native.slack.com/archives/C01NWKKMKMY
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
