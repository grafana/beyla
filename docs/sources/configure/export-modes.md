---
title: Beyla export modes
menuTitle: Export modes
description: Learn about the different export modes for Beyla.
weight: 2
keywords:
  - Beyla
  - eBPF
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/configure/export-modes/
---

# Beyla export modes

Beyla can export data in two modes:

- **Alloy mode** (recommended mode): the auto-instrumentation tool sends metrics and traces to the
  [Grafana Alloy](/docs/alloy/), which processes and sends them
  to Mimir and Tempo. In this scenario, Alloy takes care of the authentication required by the Grafana Mimir/Tempo endpoints.
  This mode also integrates better with some Grafana exclusive features,
  such as the [span-to-metrics](/docs/tempo/latest/metrics-generator/span_metrics/) and
  [span-to-service graph](/docs/tempo/latest/metrics-generator/service_graphs/) converters.
- **Direct mode**: the auto-instrumentation tool can **push** metrics and/or traces directly to a remote endpoint
  (using the OpenTelemetry/OTEL protocols) or expose a Prometheus HTTP endpoint ready to be scraped (i.e. **pull** mode).
  In the direct OTEL push mode, the auto-instrumentation tool needs to be configured with the authentication credentials.

![Beyla architecture alloy vs direct](https://grafana.com/media/docs/grafana-cloud/beyla/alloy-vs-direct.png)

<center><i>Beyla running in Alloy mode (left) vs. Direct mode (right)</i></center>

## Running in Direct mode

You can follow our [getting started tutorial](../../tutorial/getting-started/) for a quick introduction
to auto-instrumentation in Direct mode, by using OpenTelemetry. The OTLP endpoint authentication credentials are provided
by using the following environment variables:

- `OTEL_EXPORTER_OTLP_ENDPOINT`
- `OTEL_EXPORTER_OTLP_HEADERS`

To run in Direct mode by using the Prometheus scrape endpoint, please refer to the
[configuration documentation](../options/).

## Running in Alloy mode

> ℹ️ This tutorial assumes that both Alloy and the auto-instrumentation tool are installed
> as local Linux OS executables. For further examples on downloading and running the
> auto-instrumentation tool as an OCI container, you can check the documentation sections on
> [running the Beyla as a Docker container](../../setup/docker/)
> or [running Beyla in Kubernetes](../../setup/kubernetes/).

First, locally install and configure [Grafana Alloy, according to the latest documentation](/docs/alloy/).
Alloy facilitates the ingestion of OpenTelemetry metrics and traces from the auto-instrumentation tool,
and process and forward to the different Grafana product endpoints (Mimir and/or Tempo).

### Configuring Alloy pipeline

Configure the [Alloy](/docs/alloy/) pipeline and specify the following nodes:

![Beyla nodes](https://grafana.com/media/docs/grafana-cloud/beyla/nodes-2.png)

Download the [example River configuration file](https://github.com/grafana/beyla/blob/main/docs/sources/configure/resources/alloy-config.river) used in this article.

Alloy needs to expose an **OpenTelemetry receiver** endpoint, such that the auto-instrumentation tool can forward both metrics and traces.
The Alloy configuration file needs to include the following entry:

```alloy
otelcol.receiver.otlp "default" {
  grpc {}
  http {}

  output {
    metrics = [otelcol.processor.batch.default.input]
    traces = [otelcol.processor.batch.default.input]
  }
}
```

This enables reception of OpenTelemetry events via GRPC and HTTP, which will be
forwarded to the next stage in the pipeline, the **Batch processor**, which
will then accumulate the messages and forward them to the exporters:

```alloy
otelcol.processor.batch "default" {
  output {
    metrics = [otelcol.exporter.prometheus.default.input]
    traces  = [otelcol.exporter.otlp.tempo.input]
  }
}
```

You can export either metrics, traces, or both. If you only want to export a single
type of data, you can just avoid the `metrics` or `traces` lines in the previous
node definitions, and ignore some of the following exporters.

The metrics are **exported in Prometheus** format to [Grafana Mimir](/oss/mimir/).
The configuration entry will need to specify an endpoint with basic
authentication. In the provided example, the endpoint and the credentials are
provided via environment variables:

```alloy
otelcol.exporter.prometheus "default" {
    forward_to = [prometheus.remote_write.mimir.receiver]
}

prometheus.remote_write "mimir" {
  endpoint {
    url = "https://" + env("MIMIR_ENDPOINT") + "/api/prom/push"
    basic_auth {
      username = env("MIMIR_USER")
      password = env("GRAFANA_API_KEY")
    }
  }
}
```

Run Alloy with the following environment variables set:

```sh
export MIMIR_USER=734432
export MIMIR_ENDPOINT=prometheus-prod-01-eu-west-0.grafana.net
export GRAFANA_API_KEY=VHJhbGFyw60gcXVlIHRlIHbD....=
```

Finally, to **export the traces**, you will need to set up a
[Grafana Tempo](/oss/tempo/) exporter
and an endpoint, also configured via environment variables:

```alloy
otelcol.exporter.otlp "tempo" {
    client {
        endpoint = env("TEMPO_ENDPOINT")
        auth     = otelcol.auth.basic.creds.handler
    }
}

otelcol.auth.basic "creds" {
    username = env("TEMPO_USER")
    password = env("GRAFANA_API_KEY")
}
```

Please note that the `TEMPO_ENDPOINT` and `TEMPO_USER` values are different
from `MIMIR_ENDPOINT` and `MIMIR_USER`.

To run Alloy with the previous configuration (for example, written in a file named `alloy-config.river`):

```
grafana-alloy run alloy-config.river
```

### Configuring and running the auto-instrumentation tool

Configure the auto-instrumentation tool to forward data to Grafana Alloy.
This tutorial assumes Beyla and Alloy are running on the same host, so there is no need to secure the traffic nor provide authentication in the Alloy OTLP receiver.

You can configure the auto-instrumentation tool both via environment variables or via
a configuration YAML file, which is what we will use in this example.
Please refer to the complete [Configuration documentation](../options/) for
more detailed description of each configuration option.

You can download the whole [example configuration file](https://github.com/grafana/beyla/blob/main/docs/sources/configure/resources/instrumenter-config.yml),
which we will explain in the rest of this section.

First, you will need to specify the executable to instrument. If, for example,
the service executable is a process that opens the port `443`, you can use the `open_port`
property of the YAML document:

```yaml
open_port: 443
```

The auto-instrumentation tool will automatically search and instrument the process
listening on port 443.

Next, specify where the traces and the metrics are submitted.
If Alloy is running on the local host, it uses port `4318`:

```yaml
otel_metrics_export:
  endpoint: http://localhost:4318
otel_traces_export:
  endpoint: http://localhost:4318
```

You can specify both `otel_metrics_export` and `otel_traces_export` properties to
allow exporting both metrics and traces, or only one of them to export either
metrics or traces.

To run the auto-instrumentation tool (previously downloaded from the [Beyla releases page](https://github.com/grafana/beyla/releases)),
you will need to specify the path to the configuration YAML file, either with the
`-config` command-line argument or the `BEYLA_CONFIG_PATH` environment variable.
For example `instrument-config.yml`:

```
beyla -config instrument-config.yml
```

or

```
BEYLA_CONFIG_PATH=instrument-config.yml beyla
```
