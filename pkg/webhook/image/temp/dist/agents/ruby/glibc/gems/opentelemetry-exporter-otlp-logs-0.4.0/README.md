# opentelemetry-exporter-otlp-logs

The `opentelemetry-exporter-otlp-logs` gem provides an [OTLP](https://github.com/open-telemetry/opentelemetry-proto) logs exporter for OpenTelemetry for Ruby. Using `opentelemetry-exporter-otlp-logs`, an application can configure OpenTelemetry to export collected log record data to [the OpenTelemetry Collector][opentelemetry-collector-home].

## What is OpenTelemetry?

[OpenTelemetry][opentelemetry-home] is an open source observability framework, providing a general-purpose API, SDK, and related tools required for the instrumentation of cloud-native software, frameworks, and libraries.

OpenTelemetry provides a single set of APIs, libraries, agents, and collector services to capture distributed traces, metrics and logs from your application. You can analyze them using Prometheus, Jaeger, and other observability tools.

## How does this gem fit in?

The `opentelemetry-exporter-otlp-logs` gem is a plugin that provides OTLP export. To export to the OpenTelemetry Collector, an application can include this gem along with `opentelemetry-logs-sdk` and configure the SDK to use the provided OTLP exporter with a log record processor.

Generally, *libraries* that produce telemetry data should avoid depending directly on specific exporter, deferring that choice to the application developer.

### Supported protocol version

This gem supports the [v0.20.0 release][otel-proto-release] of OTLP.

## How do I get started?

Install the gem using:

```console

gem install opentelemetry-logs-sdk
gem install opentelemetry-exporter-otlp-logs

```

Or, if you use [bundler][bundler-home], include `opentelemetry-sdk` in your `Gemfile`.

Then, configure the SDK to use the OTLP exporter as a log record processor, and use the OpenTelemetry interfaces to produce log records. The following is a basic example.

```ruby
require 'opentelemetry-logs-sdk'
require 'opentelemetry/exporter/otlp_logs'

# Create a LoggerProvider
logger_provider = OpenTelemetry::SDK::Logs::LoggerProvider.new
# Create a batching processor configured to export to the OTLP exporter
processor = OpenTelemetry::SDK::Logs::Export::BatchLogRecordProcessor.new(OpenTelemetry::Exporter::OTLP::Logs::LogsExporter.new)
# Add the processor to the LoggerProvider
logger_provider.add_log_record_processor(processor)
# Access a Logger for your library from your LoggerProvider
logger = logger_provider.logger(name: 'my_app_or_gem', version: '0.1.0')

# Use your Logger to  emit a log record
logger.on_emit(
  timestamp: Time.now,
  severity_text: 'INFO',
  body: 'Thuja plicata',
  attributes: { 'cedar' => true },
)

logger_provider.shutdown
```

For additional examples, see the [examples on github][examples-github].

## How can I configure the OTLP logs exporter?

The collector exporter can be configured explicitly in code, or via environment variables. The configuration parameters, environment variables, and defaults are shown below.

| Parameter                 | Environment variable                         | Default                             |
| ------------------------- | -------------------------------------------- | ----------------------------------- |
| `endpoint:`               | `OTEL_EXPORTER_OTLP_ENDPOINT`                | `"http://localhost:4318/v1/logs"`   |
| `certificate_file:`       | `OTEL_EXPORTER_OTLP_CERTIFICATE`             |                                     |
| `client_certificate_file` | `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`      |                                     |
| `client_key_file`         | `OTEL_EXPORTER_OTLP_CLIENT_KEY`              |                                     |
| `headers:`                | `OTEL_EXPORTER_OTLP_HEADERS`                 |                                     |
| `compression:`            | `OTEL_EXPORTER_OTLP_COMPRESSION`             | `"gzip"`                            |
| `timeout:`                | `OTEL_EXPORTER_OTLP_TIMEOUT`                 | `10`                                |
| `ssl_verify_mode:`        | `OTEL_RUBY_EXPORTER_OTLP_SSL_VERIFY_PEER` or | `OpenSSL::SSL:VERIFY_PEER`          |
|                           | `OTEL_RUBY_EXPORTER_OTLP_SSL_VERIFY_NONE`    |                                     |

`ssl_verify_mode:` parameter values should be flags for server certificate verification: `OpenSSL::SSL:VERIFY_PEER` and `OpenSSL::SSL:VERIFY_NONE` are acceptable. These values can also be set using the appropriately named environment variables as shown where `VERIFY_PEER` will take precedence over `VERIFY_NONE`.  Please see [the Net::HTTP docs](https://ruby-doc.org/stdlib-2.7.6/libdoc/net/http/rdoc/Net/HTTP.html#verify_mode) for more information about these flags.

## How can I get involved?

The `opentelemetry-exporter-otlp-logs` gem source is [on github][repo-github], along with related gems including `opentelemetry-logs-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry-Ruby special interest group (SIG). You can get involved by joining us in [GitHub Discussions][discussions-url] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

## License

The `opentelemetry-exporter-otlp-logs` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

## Working with Proto Definitions

The OTel community maintains a [repository with protobuf definitions][otel-proto-github] that language and collector implementors use to generate code.

Maintainers are expected to keep up to date with the latest version of protos. This guide will provide you with step-by-step instructions on updating the OTLP Logs Exporter gem with the latest definitions.

### System Requirements

- [`git` 2.41+][git-install]
- [`protoc` 22.5][protoc-install]
- [Ruby 3+][ruby-downloads]

> :warning: `protoc 23.x` *changes the Ruby code generator to emit a serialized proto instead of a DSL.* <https://protobuf.dev/news/2023-04-20/>. Please ensure you use `protoc` version `22.x` in order to ensure we remain compatible with versions of protobuf prior to `google-protobuf` gem `3.18`.

### Upgrade Proto Definitions

**Update the target otel-proto version in the `Rakefile` that matches a release `tag` in the proto repo, e.g.**

```ruby
  # Rakefile

  # https://github.com/open-telemetry/opentelemetry-proto/tree/v0.20.0
  PROTO_VERSION = `v0.20.0`
```

**Generate the Ruby source files using `rake`:**

```console

$> bundle exec rake protobuf:generate

```

**Run tests and fix any errors:**

```console

$> bundle exec rake test

```

**Commit the changes and open a PR!**

[opentelemetry-collector-home]: https://opentelemetry.io/docs/collector/about/
[opentelemetry-home]: https://opentelemetry.io
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby/blob/main/LICENSE
[examples-github]: https://github.com/open-telemetry/opentelemetry-ruby/tree/main/examples
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
[git-install]: https://git-scm.com/book/en/v2/Getting-Started-Installing-Git
[protoc-install]: https://github.com/protocolbuffers/protobuf/releases/tag/v22.5
[ruby-downloads]: https://www.ruby-lang.org/en/downloads/
[otel-proto-github]: https://github.com/open-telemetry/opentelemetry-proto
[otel-proto-release]: https://github.com/open-telemetry/opentelemetry-proto/releases/tag/v0.20.0
