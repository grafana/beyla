---
title: Configure Beyla Prometheus and OpenTelemetry data export
menuTitle: Export data
description: Configure the Beyla components to export Prometheus and OpenTelemetry metrics and OpenTelemetry traces, including exporting to Grafana Cloud Prometheus and OTLP endpoints.
weight: 10
keywords:
  - Beyla
  - eBPF
---

<!-- vale Grafana.Paragraphs = NO -->

# Configure Beyla Prometheus and OpenTelemetry data export

Beyla can export OpenTelemetry metrics and traces to a OTLP endpoint.

To send metrics directly to the Grafana Cloud OpenTelemetry endpoint, see the [Grafana Cloud OTLP endpoint configuration](#grafana-cloud-otlp-endpoint).

## Grafana Cloud OTLP endpoint

YAML section: `grafana.otlp`

You can configure the component under the `grafana.otlp` section of your YAML configuration or via environment variables.
You can configure Beyla to submit OpenTelemetry data to the Grafana Cloud OTEL endpoint using custom variables, allowing an easier setup of the endpoint and the authentication.

For more information on the Grafana Cloud OTLP endpoint,
refer to the [Send data to the Grafana Cloud OTLP endpoint documentation](/docs/grafana-cloud/send-data/otlp/send-data-otlp/).

For example:

```yaml
grafana:
  otlp:
    cloud_submit: ["metrics", "traces"]
    cloud_zone: "eu-west-23"
    cloud_instance_id: "12345"
    cloud_api_key: "abcde"
```

You can also use the standard OpenTelemetry variables to submit the metrics and traces to any standard OpenTelemetry endpoint, including Grafana Cloud.

| YAML<p>environment variable</p>                       | Description                                                                                                                                                                                  | Type   | Default  |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | -------- |
| `cloud_submit`<p>`GRAFANA_CLOUD_SUBMIT`</p>           | A list of data types to submit to the OTLP endpoint. Accepts `metrics` and `traces` as values.                                                                                               | string | `traces` |
| `cloud_zone`<p>`GRAFANA_CLOUD_ZONE`</p>               | The cloud zone of your Grafana endpoint used to compose the Grafana OTLP URL. Refer to [cloud zone configuration](#cloud-zone-configuration) for important details about endpoint overrides. | string |          |
| `cloud_instance_id`<p>`GRAFANA_CLOUD_INSTANCE_ID`</p> | Your Grafana user name. Usually a number but must be set as a string in the YAML file.                                                                                                       | string |          |
| `cloud_api_key`<p>`GRAFANA_CLOUD_API_KEY`</p>         | API key of your Grafana Cloud account.                                                                                                                                                       | string |          |

### Cloud zone configuration

If any of the `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` variables are defined, they override the destination endpoint, and Beyla ignores the `cloud_zone` configuration option.

## OpenTelemetry metrics exporter component

YAML section: `otel_metrics_export`

Enable the OpenTelemetry metrics export component by setting the endpoint attribute in your configuration file or via an environment variable, refer to [metric export configuration options](#metrics-export-configuration-options).

Configure the component under the `otel_metrics_export` section of your YAML configuration or via environment variables.

In addition to the configuration documented in this article, the component supports environment variables from the [standard OpenTelemetry exporter configuration](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/).

For example:

```yaml
otel_metrics_export:
  ttl: 5m
  endpoint: http://otelcol:4318
  protocol: grpc
  features: ["network", "network_inter_zone"]
  buckets:
    duration_histogram: [0, 1, 2]
  histogram_aggregation: base2_exponential_bucket_histogram
```

| YAML<p>environment variable</p>                                                              | Description                                                                                                                                                                                                                                                                                                                                                    | Type            | Default                     |
| -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | --------------------------- |
| `endpoint`<p>`OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`</p>                                       | The endpoint Beyla sends metrics to.                                                                                                                                                                                                                                                                                                                           | URL             |                             |
| `OTEL_EXPORTER_OTLP_ENDPOINT`                                                                | The shared endpoint for metrics and traces exporters. Beyla adds `/v1/metrics` path to the URL when sending metrics, following the OpenTelemetry standard. To prevent this behavior, use the metrics specific setting.                                                                                                                                         | URL             |                             |
| `protocol`<p>`OTEL_EXPORTER_OTLP_METRICS_PROTOCOL`</p>                                       | The protocol transport/encoding of the OpenTelemetry endpoint, refer to [metrics export protocol](#metrics-export-protocol). [Accepted values](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/#otel_exporter_otlp_protocol) `http/json`, `http/protobuf`, and `grpc`.                                                    | string          | Inferred from port usage    |
| `OTEL_EXPORTER_OTLP_PROTOCOL`                                                                | Similar to the shared endpoint, the protocol for metrics and traces.                                                                                                                                                                                                                                                                                           | string          | Inferred from port usage    |
| `insecure_skip_verify`<p>`BEYLA_OTEL_INSECURE_SKIP_VERIFY`</p>                               | If `true`, Beyla skips verifying and accepts any server certificate. Only override this setting for non-production environments.                                                                                                                                                                                                                               | boolean         | `false`                     |
| `interval`<p>`BEYLA_METRICS_INTERVAL`</p>                                                    | The duration between exports.                                                                                                                                                                                                                                                                                                                                  | Duration        | `60s`                       |
| `features`<p>`BEYLA_OTEL_METRICS_FEATURES`</p>                                               | The list of metric groups Beyla exports data for, refer to [metrics export features](#metrics-export-features). Accepted values `application`, `application_span`, `application_host`, `application_service_graph`, `application_process`, `network` and `network_inter_zone`.                                                                                 | list of strings | `["application"]`           |
| `allow_service_graph_self_references`<p>`BEYLA_OTEL_ALLOW_SERVICE_GRAPH_SELF_REFERENCES`</p> | Controls if Beyla includes self-referencing services in service graph generation, for example a service that calls itself. Self referencing reduces service graph usefulness and increases data cardinality.                                                                                                                                                   | boolean         | `false`                     |
| `instrumentations`<p>`BEYLA_OTEL_METRICS_INSTRUMENTATIONS`</p>                               | The list of metrics instrumentation Beyla collects data for, refer to [metrics instrumentation](#metrics-instrumentation) section.                                                                                                                                                                                                                             | list of strings | `["*"]`                     |
| `buckets`                                                                                    | Sets how you can override bucket boundaries of diverse histograms, refer to [override histogram buckets](../metrics-histograms/).                                                                                                                                                                                                                              | (n/a)           | Object                      |
| `histogram_aggregation`<p>`OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION`</p>     | Sets the default aggregation Beyla uses for histogram instruments. Accepted values [`explicit_bucket_histogram`](https://opentelemetry.io/docs/specs/otel/metrics/sdk/#explicit-bucket-histogram-aggregation) or [`base2_exponential_bucket_histogram`](https://opentelemetry.io/docs/specs/otel/metrics/sdk/#base2-exponential-bucket-histogram-aggregation). | `string`        | `explicit_bucket_histogram` |

### Metrics export protocol

If you don't set a protocol Beyla sets the protocol as follows:

- `grpc`: if the port ends in `4317`, for example `4317`, `14317`, or `24317`.
- `http/protobuf`: if the port ends in `4318`, for example `4318`, `14318`, or `24318`.

### Metrics export features

The Beyla metrics exporter can export the following metrics data groups for processes matching entries in the [metrics discovery](./) configuration.

- `application`: Application-level metrics
- `application_span` Application-level trace span metrics
- `application_host` Application-level host metrics for host based pricing
- `application_service_graph`: Application-level service graph metrics.
  It's recommended to use a DNS for service discovery and to ensure the DNS names match the OpenTelemetry service names Beyla uses.
  In Kubernetes environments, the OpenTelemetry service name set by the service name discovery is the best choice for service graph metrics.
- `application_process`: Metrics about the processes that runs the instrumented application
- `network`: Network-level metrics, refer to the [network metrics](/docs/beyla/latest/network/) configuration documentation to learn more
- `network_inter_zone`: Network inter-zone metrics, refer to the [network metrics](/docs/beyla/latest/network/) configuration documentation to learn more

### Metrics instrumentation

The list of instrumentation areas Beyla can collection data from:

- `*`: all instrumentation, if `*` is present Beyla ignores other values
- `http`: HTTP/HTTPS/HTTP2 application metrics
- `grpc`: gRPC application metrics
- `sql`: SQL database client call metrics
- `redis`: Redis client/server database metrics
- `kafka`: Kafka client/server message queue metrics
- `mongodb`: MongoDB client/server database metrics

For example, setting the `instrumentations` option to: `http,grpc` enables the collection of `HTTP/HTTPS/HTTP2` and `gRPC` application metrics, and disables other instrumentation.

## OpenTelemetry traces exporter component

YAML section: `otel_traces_export`

You can configure the component under the `otel_traces_export` section of your YAML configuration or via environment variables.

In addition to the configuration documented in this article, the component supports the environment variables from the [standard OpenTelemetry exporter configuration](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/).

```yaml
otel_traces_export:
  endpoint: http://jaeger:4317
  protocol: grpc
  instrumentations: ["http, "sql"]
```

| YAML<p>environment variable</p>                                                       | Description                                                                                                                                                                                                                                                                                               | Type            | Default                  |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | ------------------------ |
| `endpoint`<p>`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`<p>`OTEL_EXPORTER_OTLP_ENDPOINT`</p> | The endpoint Beyla sends traces to. When using `OTEL_EXPORTER_OTLP_ENDPOINT`, Beyla follows the OpenTelemetry standard and automatically adds `/v1/traces` path to the URL. If you don't want this to happen, use the traces specific setting.                                                            | URL             |                          |
| `protocol`<p>`OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`<p>`OTEL_EXPORTER_OTLP_PROTOCOL`</p> | The protocol transport/encoding of the OpenTelemetry endpoint, refer to [traces export protocol](#traces-export-protocol). [Accepted values](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/#otel_exporter_otlp_protocol) `http/json`, `http/protobuf`, and `grpc`. | string          | Inferred from port usage |
| `insecure_skip_verify`<p>`BEYLA_OTEL_INSECURE_SKIP_VERIFY`</p>                        | If `true`, Beyla skips verifying and accepts any server certificate. Only override this setting for non-production environments.                                                                                                                                                                          | boolean         | `false`                  |
| `instrumentations`<p>`BEYLA_OTEL_TRACES_INSTRUMENTATIONS`</p>                         | The list of instrumentation Beyla collects data for, refer to [traces instrumentation](#traces-instrumentation) section.                                                                                                                                                                                  | list of strings | `["http", "grpc", "sql", "redis", "kafka", "mongo"]` |

### Traces export protocol

If you don't set a protocol Beyla sets the protocol as follows:

- `grpc`: if the port ends in `4317`, for example `4317`, `14317`, or `24317`.
- `http/protobuf`: if the port ends in `4318`, for example `4318`, `14318`, or `24318`.

### Traces instrumentation

The list of instrumentation areas Beyla can collection data from:

- `*`: all instrumentation, if `*` is present Beyla ignores other values
- `http`: HTTP/HTTPS/HTTP2 application traces
- `grpc`: gRPC application traces
- `sql`: SQL database client call traces
- `redis`: Redis client/server database traces
- `kafka`: Kafka client/server message queue traces
- `mongo`: MongoDB client/server database traces
- `dns`: DNS request traces (not enabled by default)
- `gpu`: GPU operation traces (not enabled by default)

For example, setting the `instrumentations` option to: `http,grpc` enables the collection of `HTTP/HTTPS/HTTP2` and `gRPC` application traces, and disables other instrumentation.

**Note**: By default, Beyla enables the most commonly used instrumentations (`http`, `grpc`, `sql`, `redis`, `kafka`, `mongo`). DNS and GPU traces are not enabled by default to reduce overhead, but can be explicitly enabled if needed.

## Prometheus exporter component

YAML section: `prometheus_export`

You can configure the component under the `prometheus_export` section of your YAML configuration or via environment variables.
This component opens an HTTP endpoint in the auto-instrumentation tool that allows any external scraper to pull metrics in Prometheus format. It is enabled if the `port` property is set.

{{< admonition type="note" >}}
The Prometheus scraper might override the values of the `instance` and `job` labels.
To keep the original values as set by Beyla,
refer to the [Grafana Alloy Prometheus scraper component documentation](/docs/alloy/latest/reference/components/prometheus/prometheus.scrape/).
{{< /admonition >}}

```yaml
prometheus_export:
  port: 8999
  path: /metrics
  extra_resource_attributes: ["deployment_environment"]
  ttl: 1s
  buckets:
    request_size_histogram: [0, 10, 20, 22]
    response_size_histogram: [0, 10, 20, 22]
  features:
    - application
    - network
    - application_process
    - application_span
    - application_service_graph
  instrumentations: ["http, "sql"]
```

| YAML<p>environment variable</p>                                                                    | Description                                                                                                                                                                                                                       | Type            | Default           |
| -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | ----------------- |
| `port`<p>`BEYLA_PROMETHEUS_PORT`</p>                                                               | The HTTP port for the Prometheus scrape endpoint. If unset or 0, no Prometheus endpoint is open.                                                                                                                                  | int             |                   |
| `path`<p>`BEYLA_PROMETHEUS_PATH`</p>                                                               | The HTTP query path to fetch the list of Prometheus metrics.                                                                                                                                                                      | string          | `/metrics`        |
| `extra_resource_attributes`<p>`BEYLA_PROMETHEUS_EXTRA_RESOURCE_ATTRIBUTES`</p>                     | A list of additional resource attributes to be added to the reported `target_info` metric. Refer to [extra resource attributes](#prometheus-extra-resource-attributes) for important details about runtime discovered attributes. | list of strings |                   |
| `ttl`<p>`BEYLA_PROMETHEUS_TTL`</p>                                                                 | The duration after which metric instances are not reported if they haven't been updated. Used to avoid reporting indefinitely finished application instances.                                                                     | Duration        | `5m`              |
| `buckets`                                                                                          | Sets how you can override bucket boundaries of diverse histograms, refer to [override histogram buckets](../metrics-histograms/).                                                                                                 | Object          |                   |
| `features`<p>`BEYLA_PROMETHEUS_FEATURES`</p>                                                       | The list of metric groups Beyla exports data for, refer to [Prometheus export features](#prometheus-export-features).                                                                                                             | list of strings | `["application"]` |
| `allow_service_graph_self_references`<p>`BEYLA_PROMETHEUS_ALLOW_SERVICE_GRAPH_SELF_REFERENCES`</p> | Does Beyla include self-referencing service in service graph generation. Self referencing isn't useful for service graphs and increases data cardinality.                                                                         | boolean         | `false`           |
| `instrumentations`<p>`BEYLA_PROMETHEUS_INSTRUMENTATIONS`</p>                                       | The list of instrumentation Beyla collects data for, refer to [Prometheus instrumentation](#prometheus-instrumentation) section.                                                                                                  | list of strings | `["*"]`           |

### Prometheus extra resource attributes

Due to internal limitations of the Prometheus API client, Beyla needs to know beforehand which attributes are exposed for each metric. This would cause that some attributes that are discovered at runtime, during instrumentation, won't be visible by default. For example, attributes defined on each application via Kubernetes annotations, or in the target application's `OTEL_RESOURCE_ATTRIBUTES` environment variable.

For example, an application defining the `OTEL_RESOURCE_ATTRIBUTES=deployment.environment=production` as environment variable, the `target_info{deployment.environment="production"}` attribute would be visible by default if the metrics are exported via OpenTelemetry but not if they are exported via Prometheus.

To make `deployment_environment` visible in Prometheus, you need to add it to the `extra_resource_attributes` list.

### Prometheus export features

The Prometheus metrics exporter can export the following metrics data groups:

- `application`: Application-level metrics
- `application_span`: Application-level trace span metrics
- `application_host` Application-level host metrics for host based pricing
- `application_service_graph`: Application-level service graph metrics.
  It's recommended to use a DNS for service discovery and to ensure the DNS names match the OpenTelemetry service names Beyla uses.
  In Kubernetes environments, the OpenTelemetry service name set by the service name discovery is the best choice for service graph metrics.
- `application_process`: Metrics about the processes that runs the instrumented application
- `network`: Network-level metrics, refer to the [network metrics](/docs/beyla/latest/network/) configuration documentation to learn more
- `network_inter_zone`: Network inter-zone metrics, refer to the [network metrics](/docs/beyla/latest/network/) configuration documentation to learn more

### Prometheus instrumentation

The list of instrumentation areas Beyla can collection data from:

- `*`: all instrumentation, if `*` is present Beyla ignores other values
- `http`: HTTP/HTTPS/HTTP2 application metrics
- `grpc`: gRPC application metrics
- `sql`: SQL database client call metrics
- `redis`: Redis client/server database metrics
- `kafka`: Kafka client/server message queue metrics

For example, setting the `instrumentations` option to: `http,grpc` enables the collection of `HTTP/HTTPS/HTTP2` and `gRPC` application metrics, and disables other instrumentation.
