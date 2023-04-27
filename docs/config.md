# Configuration

The Autoinstrumenter can be configured via environment variables or via
a YAML configuration file that is passed with the `config` command-line
argument. Environment variables have priority over the properties in the
configuration file. E.g.:

```
$ OPEN_PORT=8080 otelauto -config /path/to/config.yaml
```

At the end of this document, there is an [example of YAML configuration file](#yaml-file-example).

Currently, the Autoinstrumenter consist of a pipeline of components that
generates, transforms, and export traces from HTTP and GRPC services. In the
YAML configuration, each component has its own first-level section.

The architecture below shows the different components of the Autoinstrumenter.
Dashed boxes can be enabled and disabled according to the configuration.

```mermaid
flowchart TD
    EBPF(EBPF tracer) --> ROUT(Routes<br/>decorator)

    ROUT --> OTELM(OTEL<br/> metrics<br/> exporter)
    ROUT --> OTELT(OTEL<br/> traces<br/> exporter)

    style ROUT stroke-dasharray: 3 3;
    style OTELM stroke-dasharray: 3 3;
    style OTELT stroke-dasharray: 3 3;
```

A quick description of the components:

* [EBPF tracer](#ebpf) instruments the HTTP and GRPC services of an external Go process,
  creates service traces and forwards them to the next stage of the pipeline.
* [Routes decorator](#routes) will match HTTP paths (e.g. `/user/1234/info`)
  into user-provided HTTP routes (e.g. `/user/{id}/info`). If no routes are defined,
  the incoming data will be directly forwarded to the next stage.
* [OTEL metrics exporter](#otel_metrics) exports metrics data to an external
  [OpenTelemetry](https://opentelemetry.io/) metrics collector.
* [OTEL traces exporter](#otel_metrics) exports span data to an external
  [OpenTelemetry](https://opentelemetry.io/) traces collector.

Following sections explain both the global configuration properties, as well as
the options for each component.

## Global configuration properties

The properties in this section are first-level YAML properties, as they apply to the
whole Autoinstrumenter configuration:

| YAML        | Env var     | Type   | Default |
|-------------|-------------|--------|---------|
| `log_level` | `LOG_LEVEL` | string | `INFO`  |

Sets the level of the process standard output logger.

Valid values, from more to less verbose, are: `DEBUG`, `INFO`, `WARN` and `ERROR`

| YAML           | Env var        | Type    | Default |
|----------------|----------------|---------|---------|
| `print_traces` | `PRINT_TRACES` | boolean | `false` |
<a id="printer"></a>

If `true`, prints any instrumented trace via standard output.

## EBPF tracer (YAML section: `ebpf`)<a id="ebpf"></a>


| YAML              | Env var           | Type   | Default |
|-------------------|-------------------|--------|---------|
| `executable_name` | `EXECUTABLE_NAME` | string | (unset) |

Selects the process to instrument by its executable name path. It will match
this value as a suffix.

This property will be ignored if the `open_port` property is set.

You need to be careful to choose a non-ambiguous name. If, for example, you set
`EXECUTABLE_NAME=server`, and you have running two processes whose executables
have the following paths:

```
/usr/local/bin/language-server
/opt/app/server
```

The Autoinstrumenter will match indistinctly one of the above processes. In that
case you could refine the value to `EXECUTABLE_NAME=/opt/app/server` or just
`EXECUTABLE_NAME=/server`.

| YAML        | Env var     | Type   | Default |
|-------------|-------------|--------|---------|
| `open_port` | `OPEN_PORT` | string | (unset) |


Selects the process to instrument by the port it opens.

This property takes precedence over the `executable_name` property.

It is important to consider that, if an executable opens multiple ports, you have to
specify only one of the ports and the Autoinstrumenter **will instrument all the
HTTP and GRPC requests in all the ports**. At the moment, there is no way to
restrict the instrumentation only to the methods exposed through a single port.

| YAML         | Env var          | Type   | Default |
|--------------|------------------|--------|---------|
| `wakeup_len` | `BPF_WAKEUP_LEN` | string | (unset) |

Specifies how many messages need to be accumulated in the eBPF ringbuffer
before sending a wakeup request to the user space.

In high-load services (in terms of requests/second), this will help reducing the CPU
footprint of the Autoinstrumenter.

In low-load services (in terms of requests/second), high values of `wakeup_len` could
add a noticeable delay in the time the metrics are submitted.

## Routes decorator (YAML section: `routes`)<a id="routes"></a>

This section can be only configured via YAML. If no `routes` section is provided in
the YAML file, the routes pipeline stage is not created and data will be bypassed
to the exporters.

| YAML       | Env var | Type            | Default |
|------------|---------|-----------------|---------|
| `patterns` | --      | list of strings | (unset) |

Will match the provided URL path patterns and set the `http.route` trace/metric
property accordingly with the matching path pattern.

Each route pattern is a URL path with some inserted marks that will group any path
segment to it. The matcher marks can be in the `:name` or `{name}` format.

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
|-----------|---------|--------|------------|
| `unmatch` | --      | string | `wildcard` |

Specifies what to do when a trace HTTP path do not match any of the `patterns` entries.

Its possible values are:

* `unset` will leave the `http.route` property as unset.
* `path` will copy the `http.route` field property to the path value.
  * 🚨 Caution: this option could lead to cardinality explosion at the ingester side.
* `wildcard` will set the `http.route` field property to a generic askterisk `*` value.

## OTEL metrics exporter (YAML section: `otel_metrics`)<a id="otel_metrics"></a>

This component exports OpenTelemetry metrics to a given endpoint. It will be enabled if
its `endpoint` attribute is set (either via YAML or environment variables).

In addition to the properties exposed in this section, this component implicitly supports
the environment variables from the [standard OTEL exporter configuration](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/).

| YAML       | Env var                                                                    | Type | Default |
|------------|----------------------------------------------------------------------------|------|---------|
| `endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` or<br/>`OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | URL  | (unset) |

Specifies the OpentTelemetry endpoint where metrics will be sent.

Using the `OTEL_EXPORTER_OTLP_ENDPOINT` env var sets a common endpoint for both the metrics and
[traces](#otel_traces) exporters. Using the `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` env var
or the `endpoint` YAML property will set the endpoint only for the metrics exporter node,
so the traces exporter won't be activated unless explicitly specified.

| YAML           | Env var             | Type   | Default         |
|----------------|---------------------|--------|-----------------|
| `service_name` | `OTEL_SERVICE_NAME` | string | executable path |

Specifies the name of the instrumented service to be reported by the metrics exporter.
If unset, it will be the path of the instrumented service (e.g. `/usr/local/bin/service`).

| YAML       | Env var            | Type     | Default |
|------------|--------------------|----------|---------|
| `interval` | `METRICS_INTERVAL` | Duration | `5s`    |

Configures the intervening time between exports.

| YAML            | Env var                 | Type    | Default |
|-----------------|-------------------------|---------|---------|
| `report_target` | `METRICS_REPORT_TARGET` | boolean | `false` |

Specifies whether the exporter must submit `http.target` as a metric attribute.

According to the standard OpenTelemetry specification, `http.target` is the full HTTP request
path and query arguments.

It is disabled by default to avoid cardinality explosion in paths with IDs. As an alternative,
it is recommended to group these requests in the [routes node](#routes).

| YAML          | Env var               | Type    | Default |
|---------------|-----------------------|---------|---------|
| `report_peer` | `METRICS_REPORT_PEER` | boolean | `false` |

Specifies whether the exporter must submit the caller peer address as a metric attribute.

It is disabled by default to avoid cardinality explosion.

## OTEL traces exporter (YAML section: `otel_traces`)<a id="otel_traces"></a>

This component exports OpenTelemetry traces to a given endpoint. It will be enabled if
its `endpoint` attribute is set (either via YAML or environment variables).

In addition to the properties exposed in this section, this component implicitly supports
the environment variables from the [standard OTEL exporter configuration](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/).

| YAML       | Env var                                                                   | Type | Default |
|------------|---------------------------------------------------------------------------|------|---------|
| `endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` or<br/>`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | URL  | (unset) |

Specifies the OpentTelemetry endpoint where the traces will be sent.

Using the `OTEL_EXPORTER_OTLP_ENDPOINT` env var sets a common endpoint for both the
[metrics](#otel_metrics) and traces exporters. Using the `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` env var
or the `endpoint` YAML property will set the endpoint only for the metrics exporter node,
so the metrics exporter won't be activated unless explicitly specified.

| YAML           | Env var             | Type   | Default         |
|----------------|---------------------|--------|-----------------|
| `service_name` | `OTEL_SERVICE_NAME` | string | executable path |

Specifies the name of the instrumented service to be reported by the traces exporter.
If unset, it will be the path of the instrumented service (e.g. `/usr/local/bin/service`).

## YAML file example

```yaml
log_level: DEBUG

ebpf:
  open_port: 443
  wakeup_len: 100

otel_metrics:
  service_name: my-instrumented-service
  endpoint: https://otlp-gateway-prod-eu-west-0.grafana.net/otlp
```