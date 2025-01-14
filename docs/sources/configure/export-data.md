---
title: Export OpenTelemetry data
description: Learn how to configure the  OpenTelemetry metrics exporter.
weight: 1
keywords:
  - Beyla
  - eBPF
---

# Export OpenTelemetry data

Beyla can export OpenTelemetry metrics and traces to a OTLP endpoint.

If you want to send metrics directly to the Grafana Cloud OpenTelemetry endpoint, see the [Grafana Cloud OTLP endpoint configuration](#grafana-cloud-otlp-endpoint).

## Enable metrics export

To enable the  OpenTelemetry metrics export component, set the endpoint attribute in your configuration file or via an environment variable, refer to [metric export configuration options](#metrics-export-configuration-options).

### Metrics export configuration options

You can configure the component under the `otel_metrics_export` section of your YAML configuration or via environment variables.

In addition to the configuration documented in this article, the component supports the environment variables from the [standard OpenTelemetry exporter configuration](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/).

Beyla uses lowercase fields for YAML configuration and uppercase names for environment variable configuation.

| Lowercase YAML option<br>Uppercase environment variable option                            | Description                                                                                                                                                                                                                                                                                                                                                    | Type            | Default                     |
| ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | --------------------------- |
| `endpoint`<br>`OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`                                       | The endpoint Beyla sends metrics to.                                                                                                                                                                                                                                                                                                                           | URL             |                             |
| `OTEL_EXPORTER_OTLP_ENDPOINT`                                                             | The shared endpoint for metrics and traces exporters. Beyla follows the OpenTelemetry standard and automatically adds `/v1/metrics` path to the URL when sending metrics. If you don't want this to happen, use the metrics specific setting.                                                                                                                  | URL             |                             |
| `protocol`<br>`OTEL_EXPORTER_OTLP_METRICS_PROTOCOL`                                       | The protocol transport/encoding of the OpenTelemetry endpoint, refer to [metrics export protocol](#metrics-export-protocol). [Accepted values](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/#otel_exporter_otlp_protocol) `http/json`, `http/protobuf`, and `grpc`.                                                    | string          | Inferred from port usage    |
| `OTEL_EXPORTER_OTLP_PROTOCOL`                                                             | Similar to the shared endpoint, the protocol for metrics and traces.                                                                                                                                                                                                                                                                                           | string          | Inferred from port usage    |
| `insecure_skip_verify`<br>`BEYLA_OTEL_INSECURE_SKIP_VERIFY`                               | If `true`, Beyla skips verifying and accepts any server certificate. Only override this setting for non-production environments.                                                                                                                                                                                                                               | boolean         | `false`                     |
| `interval`<br>`BEYLA_METRICS_INTERVAL`                                                    | The duration between exports.                                                                                                                                                                                                                                                                                                                                  | Duration        | `5s`                        |
| `features`<br>`BEYLA_OTEL_METRICS_FEATURES`                                               | The list of metric groups Beyla exports data for, refer to [metrics export features](#metrics-export-features). Accepted values `application`, `application_span`, `application_service_graph`, `application_process`, and `network`.                                                                                                                          | list of strings | `["application"]`           |
| `allow_service_graph_self_references`<br>`BEYLA_OTEL_ALLOW_SERVICE_GRAPH_SELF_REFERENCES` | Does Beyla include self-referencing service in service graph generation, for example a service that calls itself. Self referencing isn't useful service graphs and increases data cardinality.                                                                                                                                                                 | boolean         | `false`                     |
| `instrumentations`<br>`BEYLA_OTEL_METRICS_INSTRUMENTATIONS`                               | The list of metrics instrumentation Beyla collects data for, refer to [metrics instrumentation](#metrics-instrumentation)  section.                                                                                                                                                                                                                            | list of strings | `["*"]`                     |
| `buckets`                                                                                 | Sets how you can override bucket boundaries of diverse histograms, refer to [override histogram buckets](#override-histogram-buckets).                                                                                                                                                                                                                         | (n/a)           | Object                      |
| `histogram_aggregation`<br>`OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION`     | Sets the default aggregation Beyla uses for histogram instruments. Accepted values [`explicit_bucket_histogram`](https://opentelemetry.io/docs/specs/otel/metrics/sdk/#explicit-bucket-histogram-aggregation) or [`base2_exponential_bucket_histogram`](https://opentelemetry.io/docs/specs/otel/metrics/sdk/#base2-exponential-bucket-histogram-aggregation). | `string`        | `explicit_bucket_histogram` |

### Metrics export protocol

If you don't set a protocol Beyla sets the protocol as follows:

- `grpc`: if the port ends in `4317`, for example `4317`, `14317`, or `24317`.
- `http/protobuf`: if the port ends in `4318`, for example `4318`, `14318`, or `24318`.

### Metrics export features

The Beyla metrics exporter can export the following metrics data groups for processes matching entries in the [metrics discovery](#metrics-discovery) configuration.

- `application`: Application-level metrics
- `application_span` Application-level trace span metrics
- `application_service_graph`: Application-level service graph metrics.
    It's recommended to use a DNS for service discovery and to ensure the DNS names match the OpenTelemetry service names Beyla uses.
    In Kubernetes environments, the OpenTelemetry service name set by the service name discovery is the best choice for service graph metrics.
- `application_process`: Metrics about the processes that runs the instrumented application
- `network`:  Network-level metrics, refer to the [network metrics](/docs/beyla/latest/network/) configuration documentation to learn more

### Metrics instrumentation

The list of instrumentation areas Beyla can collection data from:

- `*`: all instrumentation, if `*` is present Beyla ignores other values
- `http`: HTTP/HTTPS/HTTP2 application metrics
- `grpc`: gRPC application metrics
- `sql`: SQL database client call metrics
- `redis`: Redis client/server database metrics
- `kafka`: Kafka client/server message queue metrics

For example, setting the `instrumentations` option to: `http,grpc` enables the collection of `HTTP/HTTPS/HTTP2` and `gRPC` application metrics, and disables other instrumentation.

### Override histogram buckets

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

### Use native histograms and exponential histograms

For Prometheus, [native histograms](https://prometheus.io/docs/concepts/metric_types/#histogram) are enabled if you
[enable the `native-histograms` feature in your Prometheus collector](https://prometheus.io/docs/prometheus/latest/feature_flags/#native-histograms).

For OpenTelemetry you can use [exponential histograms](https://opentelemetry.io/docs/specs/otel/metrics/data-model/#exponentialhistogram)
for the predefined histograms instead of defining the buckets manually. You need to set up the standard
[OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION](https://opentelemetry.io/docs/specs/otel/metrics/sdk_exporters/otlp/#additional-configuration)
environment variable. See the `histogram_aggregation` section in the [OTEL metrics exporter](#otel-metrics-exporter) section
for more information.

## OpenTelemetry traces exporter component

> ℹ️ If you plan to use Beyla to send metrics to Grafana Cloud,
> consult the [Grafana Cloud OTEL exporter for metrics and traces](#using-the-grafana-cloud-otel-endpoint-to-ingest-metrics-and-traces)
> section for easier configuration.

YAML section `otel_traces_export`.

This component exports OpenTelemetry traces to a given endpoint. It will be enabled if
its `endpoint` attribute is set (either via an YAML configuration file or via environment variables).

In addition to the properties exposed in this section, this component implicitly supports
the environment variables from the [standard OTEL exporter configuration](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/).

| YAML       | Environment variable                                                      | Type | Default |
| ---------- | ------------------------------------------------------------------------- | ---- | ------- |
| `endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` or<br/>`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | URL  | (unset) |

Specifies the OpenTelemetry endpoint where the traces will be sent. If you plan to send the
metrics directly to the Grafana Cloud OpenTelemetry endpoint, you might prefer to use the
configuration options in the
[Using the Grafana Cloud OTEL endpoint to ingest metrics and traces](#using-the-grafana-cloud-otel-endpoint-to-ingest-metrics-and-traces)
section.

The `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable sets a common endpoint for both the
[metrics](#otel-metrics-exporter) and the traces exporters. The `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` environment variable
or the `endpoint` YAML property, will set the endpoint only for the traces' exporter node,
so the metrics exporter won't be activated unless explicitly specified.

According to the OpenTelemetry standard, if you set the endpoint via the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable,
the OpenTelemetry exporter will automatically add the `/v1/traces` path to the URL. If you want to avoid this
addition, you can use either the `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` environment variable or the `environment` YAML
property to use exactly the provided URL without any addition.

| YAML               | Environment variable                 | Type            | Default |
| ------------------ | ------------------------------------ | --------------- | ------- |
| `instrumentations` | `BEYLA_OTEL_TRACES_INSTRUMENTATIONS` | list of strings | `["*"]` |

A list of available **instrumentations** which are enabled, defined a comma separated list of strings.
By default all available **instrumentations** are enabled, and you can choose to enable only some.
The available **instrumentations** are as follows:

- `*` enables all **instrumentations**. If `*` is present in the list, the other values are simply ignored.
- `http` enables the collection of HTTP/HTTPS/HTTP2 application traces.
- `grpc` enables the collection of gRPC application traces.
- `sql` enables the collection of SQL database client call traces.
- `redis` enables the collection of Redis client/server database traces.
- `kafka` enables the collection of Kafka client/server message queue traces.

For example, setting the `instrumentations` option to: `http,grpc` enables the collection of HTTP/HTTPS/HTTP2 and
gRPC application traces, while the rest of the **instrumentations** are be disabled.

| YAML       | Environment variable                                                      | Type   | Default   |
| ---------- | ------------------------------------------------------------------------- | ------ | --------- |
| `protocol` | `OTEL_EXPORTER_OTLP_PROTOCOL` or<br/>`OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` | string | (guessed) |

Specifies the transport/encoding protocol of the OpenTelemetry traces endpoint.

The accepted values, as defined by the [OTLP Exporter Configuration document](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/#otel_exporter_otlp_protocol) are `http/json`, `http/protobuf` and `grpc`.

The `OTEL_EXPORTER_OTLP_PROTOCOL` environment variable sets a common protocol for both the metrics and
the [traces](#otel-traces-exporter) exporters. The `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` environment variable,
or the `protocol` YAML property, will set the protocol only for the traces' exporter node.

If this property is not provided, Beyla will guess it according to the following rules:

- Beyla will guess `grpc` if the port ends in `4317` (`4317`, `14317`, `24317`, ...),
  as `4317` is the usual Port number for the OTEL GRPC collector.
- Beyla will guess `http/protobuf` if the port ends in `4318` (`4318`, `14318`, `24318`, ...),
  as `4318` is the usual Port number for the OTEL HTTP collector.

| YAML                   | Environment variable              | Type    | Default |
| ---------------------- | --------------------------------- | ------- | ------- |
| `insecure_skip_verify` | `BEYLA_OTEL_INSECURE_SKIP_VERIFY` | boolean | `false` |

Controls whether the OTEL client verifies the server's certificate chain and host name.
If set to `true`, the OTEL client accepts any certificate presented by the server
and any host name in that certificate. In this mode, TLS is susceptible to a man-in-the-middle
attacks. This option should be used only for testing and development purposes.

### Sampling policy

Beyla accepts the standard OpenTelemetry environment variables to configure the
sampling ratio of traces.

In addition, you can configure the sampling under the `sampler` YAML subsection of the
`otel_traces_export` section. For example:

```yaml
otel_traces_export:
  sampler:
    name: "traceidratio"
    arg: "0.1"
```

If you are using the Grafana Alloy as your OTEL collector, you can configure the sampling
policy at that level instead.

| YAML   | Environment variable  | Type   | Default                 |
| ------ | --------------------- | ------ | ----------------------- |
| `name` | `OTEL_TRACES_SAMPLER` | string | `parentbased_always_on` |

Specifies the name of the sampler. It accepts the following standard sampler
names from the [OpenTelemetry specification](https://opentelemetry.io/docs/concepts/sdk-configuration/general-sdk-configuration/#otel_traces_sampler):

- `always_on`: samples every trace. Be careful about using this sampler in an
  application with significant traffic: a new trace will be started and exported
  for every request.
- `always_off`: samples no traces.
- `traceidratio`: samples a given fraction of traces (specified by the `arg` property
  that is explained below). The fraction must be a real value between 0 and 1.
  For example, a value of `"0.5"` would sample 50% of the traces.
  Fractions >= 1 will always sample. Fractions < 0 are treated as zero. To respect the
  parent trace's sampling configuration, the `parentbased_traceidratio` sampler should be used.
- `parentbased_always_on` (default): parent-based version of `always_on` sampler (see
  explanation below).
- `parentbased_always_off`: parent-based version of `always_off` sampler (see
  explanation below).
- `parentbased_traceidratio`: parent-based version of `traceidratio` sampler (see
  explanation below).

Parent-based samplers are composite samplers which behave differently based on the
parent of the traced span. If the span has no parent, the root sampler is used to
make sampling decision. If the span has a parent, the sampling configuration
would depend on the sampling parent.

| YAML  | Environment variable      | Type   | Default |
| ----- | ------------------------- | ------ | ------- |
| `arg` | `OTEL_TRACES_SAMPLER_ARG` | string | (unset) |

Specifies the argument of the selected sampler. Currently, only `traceidratio`
and `parentbased_traceidratio` require an argument.

In YAML, this value MUST be provided as a string, so even if the value
is numeric, make sure that it is enclosed between quotes in the YAML file,
(for example, `arg: "0.25"`).

## Prometheus HTTP endpoint

> ℹ️ The Prometheus scraper might override the values of the `instance` and `job` labels.
> To keep the original values as set by Beyla, make sure to configure the
> Prometheus scraper to set the `honor_labels` option to `true`.
>
> ([How to set `honor_labels` in Grafana Alloy](/docs/alloy/latest/reference/components/prometheus/prometheus.scrape/)).

YAML section `prometheus_export`.

This component opens an HTTP endpoint in the auto-instrumentation tool
that allows any external scraper to pull metrics in [Prometheus](https://prometheus.io/)
format. It is enabled if the `port` property is set.

| YAML   | Environment variable    | Type | Default |
| ------ | ----------------------- | ---- | ------- |
| `port` | `BEYLA_PROMETHEUS_PORT` | int  | (unset) |

Specifies the HTTP port for the Prometheus scrape endpoint. If unset or 0,
no Prometheus endpoint is open.

| YAML   | Environment variable    | Type   | Default    |
| ------ | ----------------------- | ------ | ---------- |
| `path` | `BEYLA_PROMETHEUS_PATH` | string | `/metrics` |

Specifies the HTTP query path to fetch the list of Prometheus metrics.

| YAML  | Environment variable   | Type     | Default |
| ----- | ---------------------- | -------- | ------- |
| `ttl` | `BEYLA_PROMETHEUS_TTL` | Duration | `5m`    |

The group of attributes for a metric instance is not reported anymore if the time since
the last update is greater than this Time-To-Leave (TTL) value.

The purpose of this value is to avoid reporting indefinitely finished application instances.

| YAML      | Environment variable | Type   |
| --------- | -------------------- | ------ |
| `buckets` | (n/a)                | Object |

The `buckets` object allows overriding the bucket boundaries of diverse histograms. See
[Overriding histogram buckets](#overriding-histogram-buckets) section for more details.

| YAML       | Environment variable        | Type            | Default           |
| ---------- | --------------------------- | --------------- | ----------------- |
| `features` | `BEYLA_PROMETHEUS_FEATURES` | list of strings | `["application"]` |

A list of metric groups that are allowed to be exported. Each group belongs to a different feature
of Beyla: application-level metrics or network metrics.

- If the list contains `application`, the Beyla Prometheus exporter exports application-level metrics;
  but only if the Prometheus `port` property is defined, and Beyla was able to discover any
  process matching the entries in the `discovery` section.
- If the list contains `application_span`, the Beyla Prometheus exporter exports application-level metrics in traces span metrics format;
  but only if the Prometheus `port` property is defined, and Beyla was able to discover any
  process matching the entries in the `discovery` section.
- If the list contains `application_service_graph`, the Beyla Prometheus exporter exports application-level service graph metrics;
  but only if the Prometheus `port` property is defined, and Beyla was able to discover any
  process matching the entries in the `discovery` section.
  For best experience with generating service graph metrics, use a DNS for service discovery and make sure the DNS names match
  the OpenTelemetry service names used in Beyla. In Kubernetes environments, the OpenTelemetry service name set by the service name
  discovery is the best choice for service graph metrics.
- If the list contains `application_process`, the Beyla Prometheus exporter exports metrics about the processes that
  run the instrumented application.
- If the list contains `network`, the Beyla Prometheus exporter exports network-level
  metrics; but only if the Prometheus `port` property is defined. For network-level metrics options visit the
  [network metrics]({{< relref "../network" >}}) configuration documentation.

| YAML                                  | Environment variable                                   | Type    | Default |
| ------------------------------------- | ------------------------------------------------------ | ------- | ------- |
| `allow_service_graph_self_references` | `BEYLA_PROMETHEUS_ALLOW_SERVICE_GRAPH_SELF_REFERENCES` | boolean | `false` |

This option affects the behaviour of the generation of application-level service graph metrics, which can be enabled
by adding `application_service_graph` to the list of Prometheus metric export features. By default, Beyla does not
report application-level service graph metrics which are considered to be self-referencing. For example, self-references
can be calls from local node metric scrape tools, or a service making an HTTP call to itself. Self-references
not useful for the purpose of showing service graphs, while at the same time they increase the cardinality and the
overall metric storage cost. To allow generation of application-level service graph metrics which also include
self-references, change this option value to `true`.


| YAML               | Environment variable                | Type            | Default |
| ------------------ | ----------------------------------- | --------------- | ------- |
| `instrumentations` | `BEYLA_PROMETHEUS_INSTRUMENTATIONS` | list of strings | `["*"]` |

A list of available **instrumentations** which are enabled, defined a comma separated list of strings.
By default all available **instrumentations** are enabled, and you can choose to enable only some.
The available **instrumentations** are as follows:

- `*` enables all **instrumentations**. If `*` is present in the list, the other values are simply ignored.
- `http` enables the collection of HTTP/HTTPS/HTTP2 application metrics.
- `grpc` enables the collection of gRPC application metrics.
- `sql` enables the collection of SQL database client call metrics.
- `redis` enables the collection of Redis client/server database metrics.
- `kafka` enables the collection of Kafka client/server message queue metrics.

For example, setting the `instrumentations` option to: `http,grpc` enables the collection of HTTP/HTTPS/HTTP2 and
gRPC application metrics, while the rest of the **instrumentations** are be disabled.

## Grafana Cloud OTLP endpoint

You can use the standard OpenTelemetry variables to submit the metrics and
traces to any standard OpenTelemetry endpoint, including Grafana Cloud.

Alternatively, Beyla can be configured to submit OpenTelemetry data to
the Grafana Cloud OTEL endpoint using its own custom variables, allowing an
easier setup of the endpoint and the authentication.

The properties can be defined via environment variables, or under the
`grafana` top-level YAML section, `otlp` subsection. For example:

```yaml
grafana:
  otlp:
    cloud_zone: prod-eu-west-0
    cloud_instance_id: 123456
```

| YAML           | Environment variable   | Type     | Default  |
| -------------- | ---------------------- | -------- | -------- |
| `cloud_submit` | `GRAFANA_CLOUD_SUBMIT` | []string | `traces` |

Accepts a list of strings with the kind of data that will be submitted to the
OTLP endpoint. It accepts `metrics` and/or `traces` as values.

| YAML         | Environment variable | Type   | Default |
| ------------ | -------------------- | ------ | ------- |
| `cloud_zone` | `GRAFANA_CLOUD_ZONE` | string | (unset) |

The cloud zone of your Grafana endpoint. This will be used to compose the
Grafana OTLP URL. For example, if the value is `prod-eu-west-0`, the
used OTLP URL will be `https://otlp-gateway-prod-eu-west-0.grafana.net/otlp`.

If any of the `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`
or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` variables are defined, they will
override the destination endpoint, so the `cloud_zone` configuration option
will be ignored.

| YAML                | Environment variable        | Type   | Default |
| ------------------- | --------------------------- | ------ | ------- |
| `cloud_instance_id` | `GRAFANA_CLOUD_INSTANCE_ID` | string | (unset) |

Your Grafana user name. It is usually a number but it must be set as a
string inside the YAML file.

| YAML            | Environment variable    | Type   | Default |
| --------------- | ----------------------- | ------ | ------- |
| `cloud_api_key` | `GRAFANA_CLOUD_API_KEY` | string | (unset) |

API key of your Grafana Cloud account.
