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

Configure Beyla Prometheus and OpenTelemetry metrics histograms and whether to use native histograms and exponential.

## Override histogram buckets

You can override the histogram bucket boundaries for OpenTelemetry and Prometheus metrics exporters by setting the `buckets` YAML configuration option:

| YAML                 | Type        |
| -------------------- | ----------- |
| `duration_histogram` | `[]float64` |

Sets the bucket boundaries for the metrics related to the request duration. Specifically:

- `http.server.request.duration` (OTEL) / `http_server_request_duration_seconds` (Prometheus)
- `http.client.request.duration` (OTEL) / `http_client_request_duration_seconds` (Prometheus)
- `rpc.server.duration` (OTEL) / `rpc_server_duration_seconds` (Prometheus)
- `rpc.client.duration` (OTEL) / `rpc_client_duration_seconds` (Prometheus)

If the value is unset, the default bucket boundaries follow the
[recommendation from the OpenTelemetry semantic conventions](https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/semantic_conventions/http-metrics.md)

```
0, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10
```

| YAML                     | Type        |
| ------------------------ | ----------- |
| `request_size_histogram` | `[]float64` |

Sets the bucket boundaries for the metrics related to request sizes. This is:

- `http.server.request.body.size` (OTEL) / `http_server_request_body_size_bytes` (Prometheus)
- `http.client.request.body.size` (OTEL) / `http_client_request_body_size_bytes` (Prometheus)

If the value is unset, the default bucket boundaries are:

```
0, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192
```

The default values are UNSTABLE and could change if Prometheus or OpenTelemetry semantic
conventions recommend a different set of bucket boundaries.

## Use native histograms and exponential histograms

For Prometheus, [native histograms](https://prometheus.io/docs/concepts/metric_types/#histogram) are enabled if you
[enable the `native-histograms` feature in your Prometheus collector](https://prometheus.io/docs/prometheus/latest/feature_flags/#native-histograms).

For OpenTelemetry you can use [exponential histograms](https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exponentialhistogram)
for the predefined histograms instead of defining the buckets manually. You need to set up the standard
[OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION](https://opentelemetry.io/docs/specs/otel/metrics/sdk_exporters/otlp/#additional-configuration)
environment variable. See the `histogram_aggregation` section in the [OTEL metrics exporter]({{< relref "./export-data.md" >}}) section
for more information.
