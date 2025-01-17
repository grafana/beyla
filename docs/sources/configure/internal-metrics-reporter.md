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

YAML section `internal_metrics`.

This component reports certain internal metrics about the behavior
of the auto-instrumentation tool. Currently, only [Prometheus](https://prometheus.io/) export
is supported. It is enabled if the `internal_metrics` section
contains a `prometheus` subsection with the `port` property set.

Example:

```yaml
internal_metrics:
  prometheus:
    port: 6060
    path: /internal/metrics
```

| YAML   | Environment variable                                  | Type | Default |
| ------ | ---------------------------------------- | ---- | ------- |
| `port` | `BEYLA_INTERNAL_METRICS_PROMETHEUS_PORT` | int  | (unset) |

Specifies the HTTP port for the Prometheus scrape endpoint. If unset or 0,
no Prometheus endpoint is open and no metrics are accounted.

Its value can be the same as [`prometheus_export.port`]({{< relref "./export-data.md#prometheus-http-endpoint" >}}) (both metric families
share the same HTTP server, though they can be accessed in different paths),
or a different value (two different HTTP servers for the different metric families).

| YAML   | Environment variable                                  | Type   | Default             |
| ------ | ---------------------------------------- | ------ | ------------------- |
| `path` | `BEYLA_INTERNAL_METRICS_PROMETHEUS_PATH` | string | `/internal/metrics` |

Specifies the HTTP query path to fetch the list of Prometheus metrics.
If [`prometheus_export.port`]({{< relref "./export-data.md#prometheus-http-endpoint" >}}) and `internal_metrics.prometheus.port` have the
same values, this `internal_metrics.prometheus.path` value can be
different from `prometheus_export.path`, to keep both metric families separated,
or the same (both metric families are listed in the same scrape endpoint).
