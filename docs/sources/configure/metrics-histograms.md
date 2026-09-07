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

For Prometheus, you enable [native histograms](https://prometheus.io/docs/specs/native_histograms/) with the `--enable-feature=native-histograms` feature flag (Prometheus <= 3.8.0) or with the `scrape_native_histograms` configuration setting (Prometheus >= 3.8.0).

For OpenTelemetry, you can use [exponential histograms](https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exponentialhistogram) for the predefined histograms instead of defining the buckets manually. Set the standard [OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION](https://opentelemetry.io/docs/specs/otel/metrics/sdk_exporters/otlp/#additional-configuration) environment variable. See the `histogram_aggregation` section in the [OTEL metrics exporter](../export-data/) section for more information.
