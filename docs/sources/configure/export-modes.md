---
title: Beyla export modes
menuTitle: Export modes
description: Learn about the different ways you can export metrics with Grafana's eBPF application auto-instrumentation tool.
weight: 2
---

# Beyla export modes

The eBPF auto-instrumentation tool can export data in two modes:

* **Agent mode** (recommended mode): the auto-instrumentation tool will send the metrics and the traces to the
  [Grafana Agent](https://github.com/grafana/agent), which will process and send them
  to Mimir and Tempo. In this scenario, the Agent takes care of the authentication required by the Grafana Mimir/Tempo endpoints.
  This mode also integrates better with some Grafana exclusive features,
  such as the [span-to-metrics](/docs/tempo/latest/metrics-generator/span_metrics/) and
  [span-to-service graph](/docs/tempo/latest/metrics-generator/service_graphs/) converters.
* **Direct mode**: the auto-instrumentation tool can **push** metrics and/or traces directly to a remote endpoint
  (using the OpenTelemetry/OTEL protocols) or expose a Prometheus HTTP endpoint ready to be scraped (i.e. **pull** mode).
  In the direct OTEL push mode, the auto-instrumentation tool needs to be configured with the authentication credentials.

![](https://grafana.com/media/docs/grafana-cloud/beyla/agent-vs-direct.png)

<center><i>eBPF auto-instrumentation tool running in Agent mode (left) vs. Direct mode (right)</i></center>

## Running in Direct mode

You can follow our [quick start tutorial]({{< relref "../tutorial/index.md" >}}) for a quick introduction
to auto-instrumentation in Direct mode, by using OpenTelemetry. The OTLP endpoint authentication credentials are provided
by using the following environment variables:

* `OTEL_EXPORTER_OTLP_ENDPOINT`
* `OTEL_EXPORTER_OTLP_HEADERS`

To run in Direct mode by using the Prometheus scrape endpoint, please refer to the
[configuration documentation]({{< relref "./options.md" >}}).

## Running in Agent mode

> ℹ️ This tutorial assumes that both the Agent and the auto-instrumentation tool are installed
as local Linux OS executables. For further examples on downloading and running the
auto-instrumentation tool as an OCI container, you can check the documentation sections on
[running the eBPF auto-instrumentation tool as a Docker container]({{< relref "../setup/docker.md" >}})
or [running the eBPF auto-instrumentation tool in Kubernetes]({{< relref "../kubernetes.md" >}}).

First, you will need to locally install and configure the [Grafana Agent in **Flow** mode, according to the latest documentation](/docs/agent/latest/flow/).
Running the Agent in Flow mode will facilitate the ingest of OpenTelemetry
metrics and traces from the auto-instrumentation tool, as well as process and forward
to the different Grafana product endpoints (Mimir and/or Tempo).

### Configuring the Agent pipeline

Next, you'll need to specify the following nodes by using the
[River configuration language](/docs/agent/latest/flow/config-language/):

![](https://grafana.com/media/docs/grafana-cloud/beyla/nodes.png)

You can download the [example of the whole River configuration file](/docs/grafana-cloud/monitor-applications/beyla/configure/resources/agent-config.river), which will be explained in the rest of this section.

The Agent needs to expose an **OpenTelemetry receiver** endpoint, such that the
auto-instrumentation tool can forward both metrics and traces. The Agent
configuration file will need to include the following entry:

```hcl
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

```hcl
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

```hcl
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

Assuming you have a configuration file as above, you will need to run the Agent with the environment variables set.
For example:

```sh
export MIMIR_USER=734432
export MIMIR_ENDPOINT=prometheus-prod-01-eu-west-0.grafana.net
export GRAFANA_API_KEY=VHJhbGFyw60gcXVlIHRlIHbD....=
```

Finally, to **export the traces**, you will need to setup a
[Grafana Tempo](/oss/tempo/) exporter
and an endpoint, also configured via environment variables:

```hcl
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
than `MIMIR_ENDPOINT` and `MIMIR_USER`.

To run the agent with the previous configuration (for example, written in a file
named `agent-config.river`), you need to run the following command:

```
agent run agent-config.river
```

### Configuring and running the auto-instrumentation tool

Now we can configure the auto-instrumentation tool to forward data to the running Grafana Agent.
In this tutorial we are assuming that both the auto-instrumentation tool and the Agent are
running on the same host, so there is no need to secure the traffic nor provide
authentication in the Agent OTLP receiver.

You can configure the auto-instrumentation tool both via environment variables or via
a configuration YAML file, which is what we will use in this example.
Please refer to the complete [Configuration documentation]({{< relref "./options.md" >}}) for
more detailed description of each configuration option.

You can download the whole [example configuration file](/docs/grafana-cloud/monitor-applications/beyla/configure/resources/instrumenter-config.yml),
which we will explain in the rest of this section.

First, you will need to specify the executable to instrument. If, for example,
the service executable is a process that opens the port `443`, you can use the `open_port`
property in the `ebpf` section of the YAML document:

```yaml
ebpf:
  open_port: 443
```

The auto-instrumentation tool will automatically search and instrument the process
listening on port 443.

Next, you will need to specify where the traces and the metrics will be submitted. If
the Agent is running on the local host, it will use the port `4318`:

```yaml
otel_metrics_export:
  endpoint: http://localhost:4318
otel_traces_export:
  endpoint: http://localhost:4318
```

You can specify both `otel_metrics_export` and `otel_traces_export` properties to
allow exporting both metrics and traces, or only one of them to export either
metrics or traces.

To run the auto-instrumentation tool (previously installed via `go install github.com/grafana/ebpf-autoinstrument/cmd/beyla@latest`),
you will need to specify the path to the configuration YAML file. For example `instrument-config.yml`:

```
beyla -config instrument-config.yml
```
