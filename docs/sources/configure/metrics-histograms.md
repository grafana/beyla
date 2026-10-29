---
title: Configure Beyla Prometheus and OpenTelemetry metrics histograms
menuTitle: Metrics histograms
description: Configure metrics histograms for Prometheus and OpenTelemetry, and whether to use native histograms and exponential histograms.
weight: 60
keywords:
  - Beyla
  - eBPF
---

# Configure Beyla Prometheus and OpenTelemetry metrics histograms

You can configure Beyla Prometheus and OpenTelemetry metrics histograms. You can also choose to use native histograms and exponential histograms.

## Override histogram buckets

You can override histogram bucket boundaries for the OpenTelemetry and Prometheus metrics exporters with `otel_metrics_export.buckets` and `prometheus_export.buckets`.

YAML section: `otel_metrics_export.buckets`

For example:

```yaml
otel_metrics_export:
  buckets:
    duration_histogram: [0, 1, 2]
```

| YAML                     | Type        |
| ------------------------ | ----------- |
| `duration_histogram`     | `[]float64` |
| `stat_tcp_rtt_histogram` | `[]float64` |

Set the bucket boundaries for metrics related to request duration. Specifically:

- `http.server.request.duration` (OTEL) / `http_server_request_duration_seconds` (Prometheus)
- `http.client.request.duration` (OTEL) / `http_client_request_duration_seconds` (Prometheus)
- `rpc.server.call.duration` (OTEL) / `rpc_server_call_duration_seconds` (Prometheus)
- `rpc.client.call.duration` (OTEL) / `rpc_client_call_duration_seconds` (Prometheus)

If you leave the value unset, Beyla uses the default bucket boundaries from the [OpenTelemetry semantic conventions](https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/semantic_conventions/http-metrics.md):

```
0, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10
```

YAML section: `prometheus_export.buckets`

```yaml
prometheus_export:
  buckets:
    request_size_histogram: [0, 10, 20, 22]
    response_size_histogram: [0, 10, 20, 22]
```

| YAML                      | Type        |
| ------------------------- | ----------- |
| `request_size_histogram`  | `[]float64` |
| `response_size_histogram` | `[]float64` |

Set the bucket boundaries for metrics related to request and response sizes:

- `http.server.request.body.size` (OTEL) / `http_server_request_body_size_bytes` (Prometheus)
- `http.client.request.body.size` (OTEL) / `http_client_request_body_size_bytes` (Prometheus)
- `http.server.response.body.size` (OTEL) / `http_server_response_body_size_bytes` (Prometheus)
- `http.client.response.body.size` (OTEL) / `http_client_response_body_size_bytes` (Prometheus)

If you leave the value unset, Beyla uses these default bucket boundaries:

```
0, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192
```

These default values are UNSTABLE and may change if Prometheus or OpenTelemetry semantic conventions recommend different bucket boundaries.

### TCP round-trip time buckets

The `stat_tcp_rtt_histogram` property sets the explicit bucket boundaries for `beyla.stat.tcp.rtt` (`beyla_stat_tcp_rtt_seconds` in Prometheus). Values are durations expressed in seconds.

Set the property as `otel_metrics_export.buckets.stat_tcp_rtt_histogram` or `prometheus_export.buckets.stat_tcp_rtt_histogram`.

If you leave the value unset, Beyla uses these boundaries:

```
0.0005, 0.001, 0.002, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0
```

For example, to set the boundaries for the OpenTelemetry exporter:

```yaml
otel_metrics_export:
  buckets:
    stat_tcp_rtt_histogram: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1]
```

### Runtime garbage collection buckets

Configure JVM and V8 GC duration boundaries under `otel_metrics_export.buckets` or `prometheus_export.buckets`. Values are seconds.

| Field | Metric | Default boundaries |
| --- | --- | --- |
| `jvm_gc_duration_histogram` | `jvm.gc.duration` | `[0.01, 0.1, 1, 10]` |
| `v8js_gc_duration_histogram` | `v8js.gc.duration` | `[0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10]` |

For example:

```yaml
otel_metrics_export:
  buckets:
    jvm_gc_duration_histogram: [0.01, 0.1, 0.5, 1, 5]
    v8js_gc_duration_histogram: [0.005, 0.01, 0.05, 0.1, 0.5, 1]
prometheus_export:
  port: 9090
  buckets:
    jvm_gc_duration_histogram: [0.01, 0.1, 0.5, 1, 5]
    v8js_gc_duration_histogram: [0.005, 0.01, 0.05, 0.1, 0.5, 1]
```

The exporters use their own bucket configuration. These runtime histograms retain explicit boundaries when `otel_metrics_export.histogram_aggregation` selects exponential histograms.

## Use native histograms and exponential histograms

Histogram resolution controls the balance between detail, memory use, and export payload size.

### OpenTelemetry exponential histograms

Set `otel_metrics_export.histogram_aggregation` to `base2_exponential_bucket_histogram`, or set `OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION` to that value. Configure resolution under `otel_metrics_export.exponential_histogram`:

| YAML option<p>Environment variable</p> | Description | Type | Default |
| --- | --- | --- | --- |
| `max_scale`<p>`BEYLA_METRICS_EXPONENTIAL_HISTOGRAM_MAX_SCALE`</p> | Maximum resolution scale, from `-10` to `20`. Higher values provide narrower buckets. | integer | `20` |
| `max_size`<p>`BEYLA_METRICS_EXPONENTIAL_HISTOGRAM_MAX_SIZE`</p> | Maximum bucket capacity. Must be greater than `0`. Higher values preserve more detail before reducing resolution. | integer | `160` |

For example:

```yaml
otel_metrics_export:
  histogram_aggregation: base2_exponential_bucket_histogram
  exponential_histogram:
    max_scale: 12
    max_size: 80
```

These settings apply to histograms configured through OpenTelemetry views, including HTTP, RPC, database, messaging, GenAI, service graph, and TCP round-trip time histograms. Exponential aggregation replaces their explicit bucket boundaries. Runtime GC histograms retain their explicit boundaries.

### Prometheus native histograms

Configure native histograms under `prometheus_export.native_histogram`. A compatible Prometheus server can scrape native histograms alongside classic histograms. Enable native histogram scraping with `--enable-feature=native-histograms` on Prometheus versions before 3.8.0, or `scrape_native_histograms` on Prometheus 3.8.0 or later. Refer to the [Prometheus native histogram specification](https://prometheus.io/docs/specs/native_histograms/) for server configuration.

| YAML option<p>Environment variable</p> | Description | Type | Default |
| --- | --- | --- | --- |
| `bucket_factor`<p>`BEYLA_PROMETHEUS_NATIVE_HISTOGRAM_BUCKET_FACTOR`</p> | Upper bound on the growth factor between buckets. Must be greater than `1`. Values closer to `1` provide finer resolution and use more buckets. | float | `1.1` |
| `max_bucket_number`<p>`BEYLA_PROMETHEUS_NATIVE_HISTOGRAM_MAX_BUCKET_NUMBER`</p> | Maximum populated native buckets. Must be greater than `0`. Exceeding the limit triggers a reset or a reduction in resolution. | integer | `100` |
| `min_reset_duration`<p>`BEYLA_PROMETHEUS_NATIVE_HISTOGRAM_MIN_RESET_DURATION`</p> | Minimum time between resets. Must be greater than `0`. Before this interval elapses, the histogram reduces resolution instead of resetting. | Duration | `1h` |

For example:

```yaml
prometheus_export:
  port: 9090
  native_histogram:
    bucket_factor: 1.2
    max_bucket_number: 80
    min_reset_duration: 30m
```

These controls tune the native histograms created by the application and TCP statistics exporters. They leave the classic boundaries under `prometheus_export.buckets` unchanged.

### Generative AI histogram buckets

Both exporters accept the following fields under their `buckets` section:

| Field | Metric | Unit | Default boundaries |
| --- | --- | --- | --- |
| `gen_ai_client_operation_duration_histogram` | `gen_ai.client.operation.duration` | seconds | `[0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92]` |
| `gen_ai_client_token_usage_histogram` | `gen_ai.client.token.usage` | tokens | `[1, 4, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864]` |

For example:

```yaml
otel_metrics_export:
  buckets:
    gen_ai_client_operation_duration_histogram: [0.1, 0.5, 1, 5, 10, 30, 60]
    gen_ai_client_token_usage_histogram: [16, 64, 256, 1024, 4096, 16384]
prometheus_export:
  port: 9090
  buckets:
    gen_ai_client_operation_duration_histogram: [0.1, 0.5, 1, 5, 10, 30, 60]
    gen_ai_client_token_usage_histogram: [16, 64, 256, 1024, 4096, 16384]
```

These metrics require the relevant [GenAI instrumentation](../controlling-instrumentation/#generative-ai-instrumentation). OpenTelemetry exponential aggregation replaces the explicit GenAI boundaries.
