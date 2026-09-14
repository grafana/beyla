# opentelemetry-metrics-sdk

The `opentelemetry-metrics-sdk` is an alpha implementation of the [OpenTelemetry Metrics SDK][metrics-sdk] for Ruby. It should be used in conjunction with the `opentelemetry-sdk` to collect, analyze and export metrics.

## What is OpenTelemetry?

[OpenTelemetry][opentelemetry-home] is an open source observability framework, providing a general-purpose API, SDK, and related tools required for the instrumentation of cloud-native software, frameworks, and libraries.

OpenTelemetry provides a single set of APIs, libraries, agents, and collector services to capture distributed traces, metrics, and logs from your application. You can analyze them using Prometheus, Jaeger, and other observability tools.

## How does this gem fit in?

Metrics is one of the core signals in OpenTelemetry. This package allows you to emit OpenTelemetry metrics using Ruby. It leverages an alpha implementation of the OpenTelemetry Metrics API. At the current stage, things may break and APIs may change. Use this tool with caution.

This gem does not yet have a full implementation of the Metrics SDK specification. Work is in progress.

At this time, you should be able to:

* Create all synchronous instruments:
  * `Counter`
  * `UpDownCounter`
  * `Histogram`
  * `Gauge`
* Create all asynchronous (observable) instruments:
  * `ObservableCounter`
  * `ObservableGauge`
  * `ObservableUpDownCounter`
* Use all aggregation types:
  * `ExplicitBucketHistogram` (default for histograms)
  * `ExponentialBucketHistogram`
  * `Sum` (default for counters and up-down counters)
  * `LastValue` (default for gauges)
  * `Drop`
* Configure aggregation temporality: delta, cumulative, or low-memory
* Customize metric collection with Views (filter by name, type, unit, aggregation, attribute keys)
* Export metrics using pull-based exporters:
  * `ConsoleMetricPullExporter`
  * `InMemoryMetricPullExporter` (for testing)
* Export metrics on a schedule using `PeriodicMetricReader` with any compatible push exporter (e.g. OTLP via `opentelemetry-exporter-otlp-metrics`)
* Attach exemplars to metric data points for trace correlation:
  * `AlwaysOnExemplarFilter` — every measurement is eligible
  * `AlwaysOffExemplarFilter` — no exemplars collected (default)
  * `TraceBasedExemplarFilter` — only measurements inside a sampled trace

We do not yet have support for:

* `schema_url` in view configuration

These lists are incomplete and are intended to give a broad description of what's available.

Until the Ruby implementation of OpenTelemetry Metrics becomes stable, the functionality to create and export metrics will remain in a gem separate from the stable features available from the `opentelemetry-sdk`.

## How do I get started?

Install the gems using:

```sh
gem install opentelemetry-metrics-sdk
gem install opentelemetry-sdk
```

Or, if you use [bundler][bundler-home], include `opentelemetry-metrics-sdk` and `opentelemetry-sdk` in your `Gemfile`.

Then, configure the SDK according to your desired handling of telemetry data, and use the OpenTelemetry interfaces to produces traces and other information. Following is a basic example.

```ruby
require 'opentelemetry/sdk'
require 'opentelemetry-metrics-sdk'

# Disable automatic exporter configuration so we can set one manually.
ENV['OTEL_METRICS_EXPORTER'] = 'none'

OpenTelemetry::SDK.configure

# Create an exporter and register it with the meter provider.
console_exporter = OpenTelemetry::SDK::Metrics::Export::ConsoleMetricPullExporter.new
OpenTelemetry.meter_provider.add_metric_reader(console_exporter)

# Create a meter and instrument.
meter = OpenTelemetry.meter_provider.meter('my_app')
histogram = meter.create_histogram('http.request.duration', unit: 'ms', description: 'HTTP request duration')

# Record a measurement.
histogram.record(200, attributes: { 'http.method' => 'GET', 'http.status_code' => '200' })

# Flush metrics to the exporter.
OpenTelemetry.meter_provider.metric_readers.each(&:pull)

OpenTelemetry.meter_provider.shutdown
```

### All synchronous instruments

```ruby
meter = OpenTelemetry.meter_provider.meter('my_app')

# Counter — monotonically increasing value
counter = meter.create_counter('requests.total', unit: '1', description: 'Total requests')
counter.add(1, attributes: { 'service' => 'web' })

# UpDownCounter — value that can increase or decrease
queue_depth = meter.create_up_down_counter('queue.depth', unit: '1', description: 'Items in queue')
queue_depth.add(5)
queue_depth.add(-3)

# Histogram — distribution of measurements
duration = meter.create_histogram('db.query.duration', unit: 'ms', description: 'Database query duration')
duration.record(42, attributes: { 'db.operation' => 'SELECT' })

# Gauge — current value at observation time
temperature = meter.create_gauge('system.temperature', unit: 'cel', description: 'Current temperature')
temperature.record(23.5, attributes: { 'sensor' => 'cpu' })
```

### Asynchronous (observable) instruments

Asynchronous instruments collect measurements via a callback that is invoked when the metric reader collects data.

```ruby
require 'opentelemetry/sdk'
require 'opentelemetry-metrics-sdk'

ENV['OTEL_METRICS_EXPORTER'] = 'none'
OpenTelemetry::SDK.configure

console_exporter = OpenTelemetry::SDK::Metrics::Export::ConsoleMetricPullExporter.new
OpenTelemetry.meter_provider.add_metric_reader(console_exporter)

meter = OpenTelemetry.meter_provider.meter('my_app')

# ObservableCounter — monotonically increasing, measured on demand
cpu_callback = proc { `ps -p #{Process.pid} -o %cpu=`.strip.to_f }
cpu_counter = meter.create_observable_counter('process.cpu.usage', callback: cpu_callback, unit: 'ms')

# ObservableGauge — current value, measured on demand
mem_callback = proc { `ps -p #{Process.pid} -o %mem=`.strip.to_f }
mem_gauge = meter.create_observable_gauge('process.memory.usage', callback: mem_callback, unit: 'percent')

# ObservableUpDownCounter — can increase or decrease, measured on demand
queue_callback = proc { JobQueue.current_depth }
queue_counter = meter.create_observable_up_down_counter('jobs.queue.depth', callback: queue_callback, unit: '1')

# Trigger callbacks and export
cpu_counter.observe
mem_gauge.observe
queue_counter.observe

OpenTelemetry.meter_provider.metric_readers.each(&:pull)
OpenTelemetry.meter_provider.shutdown
```

### Views

Views let you customize how metrics are collected and exported — changing the aggregation, filtering attribute keys, or dropping instruments entirely.

#### Change aggregation for a specific instrument

```ruby
require 'opentelemetry/sdk'
require 'opentelemetry-metrics-sdk'

ENV['OTEL_METRICS_EXPORTER'] = 'none'
OpenTelemetry::SDK.configure

console_exporter = OpenTelemetry::SDK::Metrics::Export::ConsoleMetricPullExporter.new
OpenTelemetry.meter_provider.add_metric_reader(console_exporter)

# Use exponential histogram aggregation for any histogram whose name contains "exponential".
# The view name supports * (match any characters) and ? (match one character) wildcards.
OpenTelemetry.meter_provider.add_view(
  '*exponential*',
  aggregation: OpenTelemetry::SDK::Metrics::Aggregation::ExponentialBucketHistogram.new(
    aggregation_temporality: :cumulative,
    max_scale: 20
  ),
  type: :histogram,
  unit: 'ms'
)

meter = OpenTelemetry.meter_provider.meter('my_app')
hist = meter.create_histogram('http.exponential.latency', unit: 'ms', description: 'Latency distribution')
(1..10).each { |i| hist.record(i ** 2, attributes: { 'env' => 'prod' }) }

OpenTelemetry.meter_provider.metric_readers.each(&:pull)
OpenTelemetry.meter_provider.shutdown
```

#### Drop an instrument

```ruby
# Drop all metrics from a specific meter — useful for suppressing noisy or low-value instrumentation.
OpenTelemetry.meter_provider.add_view(
  '*',
  aggregation: OpenTelemetry::SDK::Metrics::Aggregation::Drop.new,
  meter_name: 'noisy_library'
)
```

#### Restrict which attribute keys are retained

```ruby
# Only keep the 'http.method' and 'http.status_code' attributes; all others are dropped.
OpenTelemetry.meter_provider.add_view(
  'http.request.duration',
  attribute_keys: { 'http.method' => nil, 'http.status_code' => nil }
)
```

#### Full view options reference

```ruby
OpenTelemetry.meter_provider.add_view(
  'instrument_name_pattern',   # supports * and ? wildcards; matches against instrument name
  aggregation:   OpenTelemetry::SDK::Metrics::Aggregation::ExplicitBucketHistogram.new,
  type:          :histogram,   # instrument kind: :counter, :up_down_counter, :histogram,
                               #   :gauge, :observable_counter, :observable_gauge,
                               #   :observable_up_down_counter
  unit:          'ms',         # matches instruments with this unit
  meter_name:    'my_meter',   # matches instruments from this meter
  meter_version: '1.0',        # matches instruments from this meter version
  attribute_keys: { 'env' => nil, 'region' => nil }  # allowlist of attribute keys to retain
)
```

### Aggregation temporality

Aggregation temporality controls whether exported values represent measurements since the last export (delta) or since the process started (cumulative). Configure it globally via the environment variable or per-aggregation:

```ruby
# Via environment variable (applies to all OTLP exports):
# OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE=cumulative  (or delta, or lowmemory)

# Per-aggregation:
sum_agg = OpenTelemetry::SDK::Metrics::Aggregation::Sum.new(aggregation_temporality: :delta)
hist_agg = OpenTelemetry::SDK::Metrics::Aggregation::ExplicitBucketHistogram.new(
  aggregation_temporality: :cumulative,
  boundaries: [0, 10, 50, 100, 500, 1000]
)

OpenTelemetry.meter_provider.add_view('my_counter', aggregation: sum_agg, type: :counter)
OpenTelemetry.meter_provider.add_view('my_histogram', aggregation: hist_agg, type: :histogram)
```

| Temporality preference | Counter | Observable Counter | Histogram | UpDownCounter | Observable UpDownCounter |
| --- | --- | --- | --- | --- | --- |
| `cumulative` | Cumulative | Cumulative | Cumulative | Cumulative | Cumulative |
| `delta` | Delta | Delta | Delta | Cumulative | Cumulative |
| `lowmemory` | Delta | Cumulative | Delta | Cumulative | Cumulative |

### Periodic exporting with PeriodicMetricReader

Use `PeriodicMetricReader` to wrap any push exporter (such as the OTLP exporter) and automatically export on a schedule:

```ruby
require 'opentelemetry/sdk'
require 'opentelemetry-metrics-sdk'
require 'opentelemetry-exporter-otlp-metrics'

ENV['OTEL_METRICS_EXPORTER'] = 'none'
OpenTelemetry::SDK.configure

otlp_exporter = OpenTelemetry::Exporter::OTLP::Metrics::MetricsExporter.new
periodic_reader = OpenTelemetry::SDK::Metrics::Export::PeriodicMetricReader.new(
  export_interval_millis: 5_000,   # default: OTEL_METRIC_EXPORT_INTERVAL (60_000 ms)
  export_timeout_millis:  1_000,   # default: OTEL_METRIC_EXPORT_TIMEOUT  (30_000 ms)
  exporter: otlp_exporter
)
OpenTelemetry.meter_provider.add_metric_reader(periodic_reader)

meter  = OpenTelemetry.meter_provider.meter('my_app')
counter = meter.create_counter('requests.total', unit: '1')
counter.add(1, attributes: { 'service' => 'web' })

OpenTelemetry.meter_provider.shutdown
```

### Exemplars

Exemplars attach individual raw measurements — along with the trace context active at the time of the measurement — to an exported metric data point. This lets you jump from a metric spike directly to the trace that caused it.

By default exemplars are **disabled** (`AlwaysOffExemplarFilter`). Enable them via an environment variable or programmatically.

#### Enable via environment variable

```bash
# Eligible only when the measurement occurs inside a sampled trace (recommended)
export OTEL_METRICS_EXEMPLAR_FILTER=trace_based

# Eligible for every measurement regardless of trace context
export OTEL_METRICS_EXEMPLAR_FILTER=always_on

# Disabled (default)
export OTEL_METRICS_EXEMPLAR_FILTER=always_off
```

#### Enable programmatically

```ruby
require 'opentelemetry/sdk'
require 'opentelemetry-metrics-sdk'

ENV['OTEL_METRICS_EXPORTER'] = 'none'
OpenTelemetry::SDK.configure

exporter = OpenTelemetry::SDK::Metrics::Export::ConsoleMetricPullExporter.new
OpenTelemetry.meter_provider.add_metric_reader(exporter)

# Enable exemplar, by default using trace_based
OpenTelemetry.meter_provider.enable_exemplar_filter
```

#### AlwaysOn Exemplars and Customized Exemplars

```ruby
# Use AlwaysOn Exemplars
OpenTelemetry.meter_provider.enable_exemplar_filter(
  exemplar_filter: OpenTelemetry::SDK::Metrics::Exemplar::AlwaysOnExemplarFilter
)

# Customized Exemplars
class CustomExemplarFilter < OpenTelemetry::SDK::Metrics::Exemplar::ExemplarFilter
  def self.should_sample?(value, timestamp, attributes, context)
    # customized logic to determine should sample
  end
end

OpenTelemetry.meter_provider.enable_exemplar_filter(
  exemplar_filter: CustomExemplarFilter
)
```

#### Disabling exemplars

```ruby
OpenTelemetry.meter_provider.disable_exemplar_filter
```

### Using InMemoryMetricPullExporter for testing

```ruby
require 'opentelemetry-metrics-sdk'

exporter = OpenTelemetry::SDK::Metrics::Export::InMemoryMetricPullExporter.new
OpenTelemetry.meter_provider.add_metric_reader(exporter)

meter   = OpenTelemetry.meter_provider.meter('test_meter')
counter = meter.create_counter('test.counter', unit: '1')
counter.add(5, attributes: { 'env' => 'test' })

exporter.pull
snapshots = exporter.metric_snapshots  # Array of MetricData structs
# => [#<struct name="test.counter", data_points=[...]>]

exporter.reset  # clear accumulated snapshots between test cases
```

For additional examples, see the [examples on github][examples-github].

## How can I get involved?

The `opentelemetry-metrics-sdk` gem source is [on github][repo-github], along with related gems including `opentelemetry-sdk`.

The OpenTelemetry Ruby gems are maintained by the OpenTelemetry Ruby special interest group (SIG). You can get involved by joining us in [GitHub Discussions][discussions-url] or attending our weekly meeting. See the [meeting calendar][community-meetings] for dates and times. For more information on this and other language SIGs, see the OpenTelemetry [community page][ruby-sig].

There's still work to be done, to get to a spec-compliant metrics implementation and we'd love to have more folks contributing to the project. Check the [repo][repo-github] for issues and PRs labeled with `metrics` to see what's available.

## Feedback

During this experimental stage, we're looking for lots of community feedback about this gem. Please add your comments to Issue [#1662][1662].

## License

The `opentelemetry-metrics-sdk` gem is distributed under the Apache 2.0 license. See [LICENSE][license-github] for more information.

[metrics-sdk]: https://opentelemetry.io/docs/specs/otel/metrics/sdk/
[opentelemetry-home]: https://opentelemetry.io
[bundler-home]: https://bundler.io
[repo-github]: https://github.com/open-telemetry/opentelemetry-ruby
[license-github]: https://github.com/open-telemetry/opentelemetry-ruby/blob/main/LICENSE
[examples-github]: https://github.com/open-telemetry/opentelemetry-ruby/tree/main/examples/
[ruby-sig]: https://github.com/open-telemetry/community#ruby-sig
[community-meetings]: https://github.com/open-telemetry/community#community-meetings
[discussions-url]: https://github.com/open-telemetry/opentelemetry-ruby/discussions
[1662]: https://github.com/open-telemetry/opentelemetry-ruby/issues/1662
