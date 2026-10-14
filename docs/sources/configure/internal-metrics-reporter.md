---
title: Configure the Beyla internal metrics reporter
menuTitle: Internal metrics reporter
description: Configure how the optional internal metrics reporter component reports metrics on the internal behavior of the auto-instrumentation tool in Prometheus format.
weight: 80
keywords:
  - Beyla
  - eBPF
---

# Configure the Beyla internal metrics reporter

YAML section: `internal_metrics`

This component reports internal metrics about the auto-instrumentation tool's behavior.
You can export these metrics using [Prometheus](https://prometheus.io/) or [OpenTelemetry](https://opentelemetry.io/).

To export metrics with Prometheus, set `exporter` to `prometheus` in the `internal_metrics` section. Then set `port` in the `prometheus` subsection.

To export metrics with OpenTelemetry, set `exporter` to `otel` in the `internal_metrics` section. Then set an endpoint in the `otel_metrics_export` or `grafana.otlp` section.

Example:

```yaml
internal_metrics:
  exporter: prometheus
  prometheus:
    port: 6060
    path: /internal/metrics
  avoided_services:
    disabled: false
    limit: 2000
```

## Configuration summary

| YAML              | Environment Variable                     | Type   | Default             | Summary                                                              |
| ----------------- | ---------------------------------------- | ------ | ------------------- | -------------------------------------------------------------------- |
| `exporter`        | `BEYLA_INTERNAL_METRICS_EXPORTER`        | string | `disabled`          | [Selects the internal metrics exporter.](#internal-metrics-exporter) |
| `prometheus.port` | `BEYLA_INTERNAL_METRICS_PROMETHEUS_PORT` | int    | (unset)             | [HTTP port for Prometheus scrape endpoint.](#prometheus-port)        |
| `prometheus.path` | `BEYLA_INTERNAL_METRICS_PROMETHEUS_PATH` | string | `/internal/metrics` | [HTTP query path for Prometheus metrics.](#prometheus-path)          |
| `avoided_services.disabled` | `BEYLA_INTERNAL_METRICS_AVOIDED_SERVICES_DISABLED` | boolean | `false` | [Disables the avoided-services metric.](#avoided-services) |
| `avoided_services.limit` | `BEYLA_INTERNAL_METRICS_AVOIDED_SERVICES_LIMIT` | int | `2000` | [Limits avoided-services metric cardinality.](#avoided-services) |

## Internal metrics exporter

Set the internal metrics exporter.
You can use `disabled`, `prometheus`, or `otel`.

## Prometheus port

Set the HTTP port for the Prometheus scrape endpoint.
If you leave it unset or set it to 0, Beyla doesn't open a Prometheus endpoint and doesn't report metrics.

You can use the same value as [`prometheus_export.port`](../export-data/#prometheus-http-endpoint) (both metric families share the same HTTP server, but use different paths), or use a different value (Beyla opens two HTTP servers for the different metric families).

## Prometheus path

Set the HTTP query path to fetch Prometheus metrics.

If [`prometheus_export.port`](../export-data/#prometheus-http-endpoint) and `internal_metrics.prometheus.port` use the same value, you can set `internal_metrics.prometheus.path` to a different value than `prometheus_export.path` to keep the metric families separate, or use the same value to list both metric families in the same scrape endpoint.

## Avoided services

Beyla tracks services that it intentionally avoids instrumenting with the `beyla.avoided.services` internal metric (Prometheus name: `beyla_avoided_services`). Set `avoided_services.disabled` to `true` to prevent Beyla from creating or collecting this metric. The default is `false`.

Set `avoided_services.limit` to bound the number of metric series. The default is `2000`. A value of `0` also uses the OpenTelemetry default cardinality limit of `2000`.

Each series is identified by the service name, service namespace, and telemetry type. The service instance ID doesn't create a separate series.

The limit includes one overflow series, so Beyla reports at most `limit - 1` regular series. After Beyla reaches that capacity, it aggregates new combinations into the overflow series. OpenTelemetry marks this series with `otel.metric.overflow=true`. Prometheus uses the `otel_metric_overflow="true"` label.
