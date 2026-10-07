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
- `rpc.server.duration` (OTEL) / `rpc_server_duration_seconds` (Prometheus)
- `rpc.client.duration` (OTEL) / `rpc_client_duration_seconds` (Prometheus)

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

## Use native histograms and exponential histograms

Native and exponential histograms cover a wide value range without requiring fixed bucket boundaries. Their resolution settings balance accuracy against memory use and payload size.

### OpenTelemetry exponential histograms

To export OpenTelemetry exponential histograms, set `otel_metrics_export.histogram_aggregation` to `base2_exponential_bucket_histogram`. The settings under `otel_metrics_export.exponential_histogram` only take effect in this aggregation mode.

| YAML option<p>Environment variable</p> | Description | Type | Default |
| --------------------------------------- | ----------- | ---- | ------- |
| `max_scale`<p>`BEYLA_METRICS_EXPONENTIAL_HISTOGRAM_MAX_SCALE`</p> | Maximum histogram scale. Higher scales use narrower buckets and preserve more detail, but can require more buckets. Valid values range from `-10` through `20`. | integer | `20` |
| `max_size`<p>`BEYLA_METRICS_EXPONENTIAL_HISTOGRAM_MAX_SIZE`</p> | Maximum number of buckets. Higher values reduce bucket compaction and preserve more detail at the cost of memory and larger metric payloads. Must be greater than `0`. | integer | `160` |

For example, the following configuration limits exponential histograms to 80 buckets with a maximum scale of 12:

```yaml
otel_metrics_export:
  histogram_aggregation: base2_exponential_bucket_histogram
  exponential_histogram:
    max_scale: 12
    max_size: 80
```

Explicit boundaries under `otel_metrics_export.buckets` don't apply when you select exponential aggregation.

### Prometheus native histograms

For Prometheus, enable [native histograms](https://prometheus.io/docs/specs/native_histograms/) with the `--enable-feature=native-histograms` feature flag (Prometheus versions earlier than 3.8.0) or with the `scrape_native_histograms` configuration setting (Prometheus 3.8.0 or later).

| YAML option<p>Environment variable</p> | Description | Type | Default |
| --------------------------------------- | ----------- | ---- | ------- |
| `bucket_factor`<p>`BEYLA_PROMETHEUS_NATIVE_HISTOGRAM_BUCKET_FACTOR`</p> | Upper bound for the growth factor between consecutive buckets. Values closer to `1` provide finer resolution and use more buckets. Must be greater than `1`. | float | `1.1` |
| `max_bucket_number`<p>`BEYLA_PROMETHEUS_NATIVE_HISTOGRAM_MAX_BUCKET_NUMBER`</p> | Maximum number of populated native histogram buckets. When the limit is exceeded, the histogram resets or reduces its resolution. Must be greater than `0`. | integer | `100` |
| `min_reset_duration`<p>`BEYLA_PROMETHEUS_NATIVE_HISTOGRAM_MIN_RESET_DURATION`</p> | Minimum time between histogram resets. Before this interval elapses, an over-limit histogram reduces its resolution instead of resetting. Must be greater than `0`. | Duration | `1h` |

Configure these settings under `prometheus_export.native_histogram`. For example:

```yaml
prometheus_export:
  port: 9090
  native_histogram:
    bucket_factor: 1.2
    max_bucket_number: 80
    min_reset_duration: 30m
```

Prometheus native histogram settings don't change the explicit buckets configured under `prometheus_export.buckets`. A compatible Prometheus server can scrape the native histogram alongside explicitly configured classic buckets.
