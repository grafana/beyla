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

By default, Beyla uses [native histograms](https://prometheus.io/docs/concepts/metric_types/#histogram)
for Prometheus and [exponential histograms](https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exponentialhistogram)
for OpenTelemetry. These formats provide higher precision and lower cardinality than explicit-bucket histograms without requiring manual bucket configuration.

You can override this behavior by configuring explicit bucket boundaries.

## Native histograms (Prometheus)

Beyla emits Prometheus metrics using [native histograms](https://prometheus.io/docs/concepts/metric_types/#histogram) by default. No bucket configuration is required on the Beyla side.

To receive native histograms, your Prometheus collector must have the [`native-histograms` feature flag enabled](https://prometheus.io/docs/prometheus/latest/feature_flags/#native-histograms).

If you need to revert to explicit-bucket histograms, set the bucket boundaries explicitly under `prometheus_export.buckets` as described in the [Override histogram buckets](#override-histogram-buckets) section below.

## Exponential histograms (OpenTelemetry)

Beyla uses [exponential histograms](https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exponentialhistogram) for OpenTelemetry metrics by default. This is controlled by the `histogram_aggregation` option in the `otel_metrics_export` section, which defaults to `base2_exponential_bucket_histogram`.

To revert to explicit-bucket histograms, set `histogram_aggregation` to `explicit_bucket_histogram` (or set the `OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION` environment variable):

```yaml
otel_metrics_export:
  histogram_aggregation: explicit_bucket_histogram
```

See the `histogram_aggregation` option in the [OTEL metrics exporter](../export-data/) section for more information.

## Override histogram buckets

You can override the histogram bucket boundaries for OpenTelemetry and Prometheus metrics exporters by setting the `buckets` YAML configuration option. Setting explicit buckets also switches the exporter from native/exponential to explicit-bucket mode for the affected histograms.

YAML section: `otel_metrics_export.buckets`

For example:

```yaml
otel_metrics_export:
  histogram_aggregation: explicit_bucket_histogram
  buckets:
    duration_histogram: [0, 1, 2]
```

| YAML                 | Type        |
| -------------------- | ----------- |
| `duration_histogram` | `[]float64` |

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
