---
title: Beyla configuration options
menuTitle: Options
description: Learn about the configuration options available for Beyla.
weight: 1
keywords:
  - Beyla
  - eBPF
---

# Beyla configuration options

Beyla can be configured via environment variables or via
a YAML configuration file that is passed with the `-config` command-line
argument. Environment variables have priority over the properties in the
configuration file. For example, in the following command line, the OPEN_PORT option,
is used to override any open_port settings inside the config.yaml file:

```
$ OPEN_PORT=8080 beyla -config /path/to/config.yaml
```

At the end of this document, there is an [example of YAML configuration file](#yaml-file-example).

Currently, Beyla consist of a pipeline of components which
generate, transform, and export traces from HTTP and GRPC services. In the
YAML configuration, each component has its own first-level section.

The architecture below shows the different components of Beyla.
The dashed boxes in the diagram below can be enabled and disabled according to the configuration.

![Grafana Beyla architecture](https://grafana.com/media/docs/grafana-cloud/beyla/architecture.png)

A quick description of the components:

- [EBPF tracer](#ebpf-tracer) instruments the HTTP and GRPC services of an external process,
  creates service traces and forwards them to the next stage of the pipeline.
- [Routes decorator](#routes-decorator) will match HTTP paths (e.g. `/user/1234/info`)
  into user-provided HTTP routes (e.g. `/user/{id}/info`). If no routes are defined,
  the incoming data will be directly forwarded to the next stage.
- [OTEL metrics exporter](#otel-metrics-exporter) exports metrics data to an external
  [OpenTelemetry](https://opentelemetry.io/) metrics collector.
- [OTEL traces exporter](#otel-traces-exporter) exports span data to an external
  [OpenTelemetry](https://opentelemetry.io/) traces collector.
- [Prometheus HTTP endpoint](#prometheus-http-endpoint) enables an HTTP endpoint
  that allows any external scraper to pull metrics in [Prometheus](https://prometheus.io/) format.
- [Internal metrics reporter](#internal-metrics-reporter) optionally reports metrics about the internal behavior of
  the auto-instrumentation tool in [Prometheus](https://prometheus.io/) format.

The following sections explain the global configuration properties, as well as
the options for each component.

## Global configuration properties

The properties in this section are first-level YAML properties, as they apply to the
whole Beyla configuration:

| YAML              | Env var           | Type   | Default |
| ----------------- | ----------------- | ------ | ------- |
| `executable_name` | `EXECUTABLE_NAME` | string | (unset) |

Selects the process to instrument by the executable name path. The tool will match
this value as a suffix on the full executable command line, including the directory
where the executable resides on the file system.

This property will be ignored if the `open_port` property is set.

When instrumenting by using the executable name, choose a non-ambiguous name, a name that
will match a single executable on the target system.
For example, if you set `EXECUTABLE_NAME=server`, and you have running two processes whose executables
have the following paths:

```sh
/usr/local/bin/language-server
/opt/app/server
```

Beyla will match indistinctly one of the above processes. To avoid this
issue, you should be as concrete as possible about the value of the setting. For example, `EXECUTABLE_NAME=/opt/app/server`
or just `EXECUTABLE_NAME=/server`.

| YAML        | Env var     | Type   | Default |
| ----------- | ----------- | ------ | ------- |
| `open_port` | `OPEN_PORT` | string | (unset) |

Selects the process to instrument by the port it has open (listens to).

This property takes precedence over the `executable_name` property.

If an executable opens multiple ports, only one of the ports needs to be specified
for Beyla **to instrument all the
HTTP/S and GRPC requests on all application ports**. At the moment, there is no way to
restrict the instrumentation only to the methods exposed through a specific port.

| YAML          | Env var       | Type    | Default |
| ------------- | ------------- | ------- | ------- |
| `system_wide` | `SYSTEM_WIDE` | boolean | false   |

Causes instrumentation of all processes on the system. This includes all
existing processes, and all newly launched processes after the instrumentation
has been enabled.

This property is mutually exclusive with the `executable_name` and `open_port` properties.

At present time only HTTP (non SSL) requests are tracked system-wide, and there's no support for gRPC yet.
When you are instrumenting Go applications, you should explicitly use `executable_name` or
`open_port` instead of `system_wide` instrumentation. The Go specific instrumentation is of higher
fidelity and incurs lesser overall overhead.

| YAML           | Env var                               | Type   | Default         |
| -------------- |---------------------------------------| ------ | --------------- |
| `service_name` | `SERVICE_NAME` or `OTEL_SERVICE_NAME` | string | executable name |

Overrides the name of the instrumented service to be reported by the metrics exporter.
If unset, it will be the name of the executable of the service.

| YAML                | Env var             | Type   | Default |
| ------------------- | ------------------- | ------ | ------- |
| `service_namespace` | `SERVICE_NAMESPACE` | string | (unset) |

Optionally, allows assigning a namespace for the service.

| YAML        | Env var     | Type   | Default |
| ----------- | ----------- | ------ | ------- |
| `log_level` | `LOG_LEVEL` | string | `INFO`  |

Sets the verbosity level of the process standard output logger.
Valid log level values are: `DEBUG`, `INFO`, `WARN` and `ERROR`.
`DEBUG` being the most verbose and `ERROR` the least verbose.

| YAML           | Env var        | Type    | Default |
| -------------- | -------------- | ------- | ------- |
| `print_traces` | `PRINT_TRACES` | boolean | `false` |

<a id="printer"></a>

If `true`, prints any instrumented trace on the standard output (stdout).

| YAML                       | Env var                    | Type    | Default |
| -------------------------- | -------------------------- | ------- | ------- |
| `skip_go_specific_tracers` | `SKIP_GO_SPECIFIC_TRACERS` | boolean | false   |

Disables the detection of Go specifics when ebpf tracer inspects executables to be instrumented.
The tracer will fallback to using generic instrumentation, which will generally be less efficient.

## EBPF tracer

YAML section `ebpf`.

| YAML         | Env var          | Type   | Default |
| ------------ | ---------------- | ------ | ------- |
| `wakeup_len` | `BPF_WAKEUP_LEN` | string | (unset) |

Specifies how many messages need to be accumulated in the eBPF ringbuffer
before sending a wake-up request to the user space code.

In high-load services (in terms of requests/second), tuning this option to higher values
can help with reducing the CPU overhead of Beyla.

In low-load services (in terms of requests/second), high values of `wakeup_len` could
add a noticeable delay in the time the metrics are submitted and become externally visible.


## Routes decorator

YAML section `routes`.

This section can be only configured via the YAML file. If no `routes` section is provided in
the YAML file, a default routes' pipeline stage will be created and filtered with the `wildcard`
routes decorator.

| YAML       | Env var | Type            | Default |
| ---------- | ------- | --------------- | ------- |
| `patterns` | --      | list of strings | (unset) |

Will match the provided URL path patterns and set the `http.route` trace/metric
property accordingly. You should use the `routes` property
whenever possible to reduce the cardinality of generated metrics.

Each route pattern is a URL path with specific tags which allow for grouping path
segments. The matcher tags can be in the `:name` or `{name}` format.

For example, if you define the following patterns:

```yaml
routes:
  patterns:
    - /user/{id}
    - /user/{id}/basket/{product}
```

Traces with the following HTTP paths will include the same `http.route='/user/{id}'` property:

```
/user/123
/user/456
```

Traces with the following HTTP paths will include the same `http.route='/user/{id}'/basket/{product}`
property:

```
/user/123/basket/1
/user/456/basket/3
```

| YAML      | Env var | Type   | Default    |
| --------- | ------- | ------ | ---------- |
| `unmatch` | --      | string | `wildcard` |

Specifies what to do when a trace HTTP path does not match any of the `patterns` entries.

Possible values for the `unmatch` property are:

- `unset` will leave the `http.route` property as unset.
- `path` will copy the `http.route` field property to the path value.
  - 🚨 Caution: this option could lead to cardinality explosion at the ingester side.
- `wildcard` will set the `http.route` field property to a generic asterisk based `/**` value.

## OTEL metrics exporter

YAML section `otel_metrics`.

This component exports OpenTelemetry metrics to a given endpoint. It will be enabled if
its `endpoint` attribute is set (either via an YAML configuration file or via environment variables).

In addition to the properties exposed in this section, this component implicitly supports
the environment variables from the [standard OTEL exporter configuration](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/).

| YAML       | Env var                                                                    | Type | Default |
| ---------- | -------------------------------------------------------------------------- | ---- | ------- |
| `endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` or<br/>`OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | URL  | (unset) |

Specifies the OpenTelemetry endpoint where metrics will be sent.

The `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable sets a common endpoint for both the metrics and the
[traces](#otel-traces-exporter) exporters. The `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` environment variable,
or the `endpoint` YAML, property will set the endpoint only for the metrics exporter node,
such that the traces' exporter won't be activated unless explicitly specified.

According to the OpenTelemetry standard, if you set the endpoint via the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable,
the OpenTelemetry exporter will automatically add the `/v1/metrics` path to the URL. If you want to avoid this
addition, you can use either the `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` environment variable or the `environment` YAML
property to use exactly the provided URL without any addition.

| YAML       | Env var                                                                    | Type   | Default   |
| ---------- | -------------------------------------------------------------------------- | ------ |-----------|
| `protocol` | `OTEL_EXPORTER_OTLP_PROTOCOL` or<br/>`OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` | string | (guessed) |

Specifies the transport/encoding protocol of the OpenTelemetry endpoint.

The accepted values, as defined by the [OTLP Exporter Configuration document](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/#otel_exporter_otlp_protocol) are `http/json`, `http/protobuf` and `grpc`.

The `OTEL_EXPORTER_OTLP_PROTOCOL` environment variable sets a common protocol for both the metrics and
[traces](#otel-traces-exporter) exporters. The `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` environment variable,
or the `protocol` YAML property, will set the protocol only for the metrics exporter node.

If this property is not provided, Beyla will guess it according to the following rules:

* Beyla will guess `grpc` if the port ends in `4317` (`4317`, `14317`, `24317`, ...),
  as `4317` is the usual Port number for the OTEL GRPC collector.
* Beyla will guess `http/protobuf` if the port ends in `4318` (`4318`, `14318`, `24318`, ...),
  as `4318` is the usual Port number for the OTEL HTTP collector.

| YAML                   | Env var                     | Type | Default |
| ---------------------- | --------------------------- | ---- | ------- |
| `insecure_skip_verify` | `OTEL_INSECURE_SKIP_VERIFY` | bool | `false` |

Controls whether the OTEL client verifies the server's certificate chain and host name.
If set to `true`, the OTEL client accepts any certificate presented by the server
and any host name in that certificate. In this mode, TLS is susceptible to a man-in-the-middle
attacks. This option should be used only for testing and development purposes.

| YAML       | Env var            | Type     | Default |
| ---------- | ------------------ | -------- | ------- |
| `interval` | `METRICS_INTERVAL` | Duration | `5s`    |

Configures the intervening time between exports.

| YAML            | Env var                 | Type    | Default |
| --------------- | ----------------------- | ------- | ------- |
| `report_target` | `METRICS_REPORT_TARGET` | boolean | `false` |

Specifies whether the exporter must submit `http.target` as a metric attribute.

According to the standard OpenTelemetry specification, `http.target` is the full HTTP request
path and query arguments.

It is disabled by default to avoid cardinality explosion in paths with IDs. As an alternative,
it is recommended to group these requests in the [routes' node](#routes-decorator).

| YAML          | Env var               | Type    | Default |
| ------------- | --------------------- | ------- | ------- |
| `report_peer` | `METRICS_REPORT_PEER` | boolean | `false` |

Specifies whether the exporter must submit the caller peer address as a metric attribute.

It is disabled by default to avoid cardinality explosion.

| YAML      | Env var | Type   |
| --------- | ------- | ------ |
| `buckets` | (n/a)   | Object |

The `buckets` object allows overriding the bucket boundaries of diverse histograms. See
[Overriding histogram buckets](#overriding-histogram-buckets) section for more details.

### Overriding histogram buckets

For both OpenTelemetry and Prometheus metrics exporters, you can override the histogram bucket
boundaries via a configuration file (see `buckets` YAML section of your metrics exporter configuration).

| YAML                 | Type        |
| -------------------- | ----------- |
| `duration_histogram` | `[]float64` |

Sets the bucket boundaries for the metrics related to the request duration. Specifically:

- `http.server.duration` (OTEL) / `http_server_duration_seconds` (Prometheus)
- `http.client.duration` (OTEL) / `http_client_duration_seconds` (Prometheus)
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

- `http.server.request.size` (OTEL) / `http_server_request_size_bytes` (Prometheus)
- `http.client.request.size` (OTEL) / `http_client_request_size_bytes` (Prometheus)

If the value is unset, the default bucket boundaries are:

```
0, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192
```

The default values are UNSTABLE and could change if Prometheus or OpenTelemetry semantic
conventions recommend a different set of bucket boundaries.

## OTEL traces exporter

YAML section `otel_traces`.

This component exports OpenTelemetry traces to a given endpoint. It will be enabled if
its `endpoint` attribute is set (either via an YAML configuration file or via environment variables).

In addition to the properties exposed in this section, this component implicitly supports
the environment variables from the [standard OTEL exporter configuration](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/).

| YAML       | Env var                                                                   | Type | Default |
| ---------- | ------------------------------------------------------------------------- | ---- | ------- |
| `endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` or<br/>`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | URL  | (unset) |

Specifies the OpenTelemetry endpoint where the traces will be sent.

The `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable sets a common endpoint for both the
[metrics](#otel-metrics-exporter) and the traces exporters. The `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` environment variable
or the `endpoint` YAML property, will set the endpoint only for the traces' exporter node,
so the metrics exporter won't be activated unless explicitly specified.

According to the OpenTelemetry standard, if you set the endpoint via the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable,
the OpenTelemetry exporter will automatically add the `/v1/traces` path to the URL. If you want to avoid this
addition, you can use either the `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` environment variable or the `environment` YAML
property to use exactly the provided URL without any addition.

| YAML       | Env var                                                                   | Type   | Default   |
| ---------- | ------------------------------------------------------------------------- | ------ |-----------|
| `protocol` | `OTEL_EXPORTER_OTLP_PROTOCOL` or<br/>`OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` | string | (guessed) |

Specifies the transport/encoding protocol of the OpenTelemetry traces endpoint.

The accepted values, as defined by the [OTLP Exporter Configuration document](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/#otel_exporter_otlp_protocol) are `http/json`, `http/protobuf` and `grpc`.

The `OTEL_EXPORTER_OTLP_PROTOCOL` environment variable sets a common protocol for both the metrics and
the [traces](#otel-traces-exporter) exporters. The `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` environment variable,
or the `protocol` YAML property, will set the protocol only for the traces' exporter node.

If this property is not provided, Beyla will guess it according to the following rules:

* Beyla will guess `grpc` if the port ends in `4317` (`4317`, `14317`, `24317`, ...),
  as `4317` is the usual Port number for the OTEL GRPC collector.
* Beyla will guess `http/protobuf` if the port ends in `4318` (`4318`, `14318`, `24318`, ...),
  as `4318` is the usual Port number for the OTEL HTTP collector.

| YAML                   | Env var                     | Type | Default |
| ---------------------- | --------------------------- | ---- | ------- |
| `insecure_skip_verify` | `OTEL_INSECURE_SKIP_VERIFY` | bool | `false` |

Controls whether the OTEL client verifies the server's certificate chain and host name.
If set to `true`, the OTEL client accepts any certificate presented by the server
and any host name in that certificate. In this mode, TLS is susceptible to a man-in-the-middle
attacks. This option should be used only for testing and development purposes.

| YAML             | Env var                     | Type  | Default |
| ---------------- | --------------------------- | ----- | ------- |
| `sampling_ratio` | `OTEL_TRACE_SAMPLING_RATIO` | float | `1.0`   |

Specifies the ratio of generated traces that will be sampled for sending to an OTEL collector.
By default, all traces are sampled, meaning that all traces will be sent downstream. In production, you
may want to lower this number to reduce the amount of generated trace data. If you are using the
Grafana Agent as your OTEL collector, you can configure the sampling policy at that level instead.

## Prometheus HTTP endpoint

YAML section `prometheus_export`.

This component opens an HTTP endpoint in the auto-instrumentation tool
that allows any external scraper to pull metrics in [Prometheus](https://prometheus.io/)
format. It will be enabled if the `port` property is set.

| YAML   | Env var                 | Type | Default |
| ------ | ----------------------- | ---- | ------- |
| `port` | `BEYLA_PROMETHEUS_PORT` | int  | (unset) |

Specifies the HTTP port for the Prometheus scrape endpoint. If unset or 0,
no Prometheus endpoint will be open.

| YAML   | Env var           | Type   | Default    |
| ------ | ----------------- | ------ | ---------- |
| `path` | `PROMETHEUS_PATH` | string | `/metrics` |

Specifies the HTTP query path to fetch the list of Prometheus metrics.

| YAML            | Env var                 | Type    | Default |
| --------------- | ----------------------- | ------- | ------- |
| `report_target` | `METRICS_REPORT_TARGET` | boolean | `false` |

Specifies whether the exporter must submit `http_target` as a metric attribute.

To be consistent with the OpenTelemetry specification, `http_target` is the full HTTP request
path and query arguments.

It is disabled by default to avoid cardinality explosion in paths with IDs. As an alternative,
it is recommended to group these requests in the [routes' node](#routes-decorator).

| YAML          | Env var               | Type    | Default |
| ------------- | --------------------- | ------- | ------- |
| `report_peer` | `METRICS_REPORT_PEER` | boolean | `false` |

Specifies whether the exporter must submit the caller peer address as a metric attribute.

It is disabled by default to avoid cardinality explosion.

| YAML      | Env var | Type   |
| --------- | ------- | ------ |
| `buckets` | (n/a)   | Object |

The `buckets` object allows overriding the bucket boundaries of diverse histograms. See
[Overriding histogram buckets](#overriding-histogram-buckets) section for more details.

## Internal metrics reporter

YAML section `internal_metrics`.

This component will report certain internal metrics about the behavior
of the auto-instrumentation tool, and expose them as a [Prometheus](https://prometheus.io/)
scraper. It will be enabled if the `port` property is set.

| YAML   | Env var                            | Type | Default |
| ------ | ---------------------------------- | ---- | ------- |
| `port` | `INTERNAL_METRICS_PROMETHEUS_PORT` | int  | (unset) |

Specifies the HTTP port for the Prometheus scrape endpoint. If unset or 0,
no Prometheus endpoint will be open and no metrics will be accounted.

Its value can be the same as [`prometheus_export.port`](#prometheus-http-endpoint) (both metric families
will share the same HTTP server, though they can be accessed in different paths),
or a different value (two different HTTP servers for the different metric families).

| YAML   | Env var                            | Type   | Default             |
| ------ | ---------------------------------- | ------ | ------------------- |
| `path` | `INTERNAL_METRICS_PROMETHEUS_PATH` | string | `/internal/metrics` |

Specifies the HTTP query path to fetch the list of Prometheus metrics.
If [`prometheus_export.port`](#prometheus-http-endpoint) and `internal_metrics.port` have the
same values, this `internal_metrics.path` value can be
different from `prometheus_export.path`, to keep both metric families separated,
or the same (both metric families will be listed in the same scrape endpoint).

## YAML file example

```yaml
open_port: 443
service_name: my-instrumented-service
log_level: DEBUG

ebpf:
  wakeup_len: 100

otel_traces:
  endpoint: https://otlp-gateway-prod-eu-west-0.grafana.net/otlp

prometheus_export:
  port: 8999
  path: /metrics
```
