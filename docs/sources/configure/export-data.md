
## OTEL metrics exporter

> ℹ️ If you plan to use Beyla to send metrics to Grafana Cloud,
> consult the [Grafana Cloud OTEL exporter for metrics and traces](#using-the-grafana-cloud-otel-endpoint-to-ingest-metrics-and-traces)
> section for easier configuration.

YAML section `otel_metrics_export`.

This component exports OpenTelemetry metrics to a given endpoint. It will be enabled if
its `endpoint` attribute is set (either via an YAML configuration file or via environment variables).

In addition to the properties exposed in this section, this component implicitly supports
the environment variables from the [standard OTEL exporter configuration](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/).

| YAML       | Environment variable                                                                    | Type | Default |
| ---------- | -------------------------------------------------------------------------- | ---- | ------- |
| `endpoint` | `OTEL_EXPORTER_OTLP_ENDPOINT` or<br/>`OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | URL  | (unset) |

Specifies the OpenTelemetry endpoint where metrics will be sent. If you plan to send the
metrics directly to the Grafana Cloud OpenTelemetry endpoint, you might prefer to use the
configuration options in the
[Using the Grafana Cloud OTEL endpoint to ingest metrics and traces](#using-the-grafana-cloud-otel-endpoint-to-ingest-metrics-and-traces)
section.

The `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable sets a common endpoint for both the metrics and the
[traces](#otel-traces-exporter) exporters. The `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` environment variable,
or the `endpoint` YAML, property will set the endpoint only for the metrics exporter node,
such that the traces' exporter won't be activated unless explicitly specified.

According to the OpenTelemetry standard, if you set the endpoint via the `OTEL_EXPORTER_OTLP_ENDPOINT` environment variable,
the OpenTelemetry exporter will automatically add the `/v1/metrics` path to the URL. If you want to avoid this
addition, you can use either the `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` environment variable or the `environment` YAML
property to use exactly the provided URL without any addition.

| YAML       | Environment variable                                                                    | Type   | Default   |
| ---------- | -------------------------------------------------------------------------- | ------ | --------- |
| `protocol` | `OTEL_EXPORTER_OTLP_PROTOCOL` or<br/>`OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` | string | (guessed) |

Specifies the transport/encoding protocol of the OpenTelemetry endpoint.

The accepted values, as defined by the [OTLP Exporter Configuration document](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/#otel_exporter_otlp_protocol) are `http/json`, `http/protobuf` and `grpc`.

The `OTEL_EXPORTER_OTLP_PROTOCOL` environment variable sets a common protocol for both the metrics and
[traces](#otel-traces-exporter) exporters. The `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` environment variable,
or the `protocol` YAML property, will set the protocol only for the metrics exporter node.

If this property is not provided, Beyla will guess it according to the following rules:

- Beyla will guess `grpc` if the port ends in `4317` (`4317`, `14317`, `24317`, ...),
  as `4317` is the usual Port number for the OTEL GRPC collector.
- Beyla will guess `http/protobuf` if the port ends in `4318` (`4318`, `14318`, `24318`, ...),
  as `4318` is the usual Port number for the OTEL HTTP collector.

| YAML                   | Environment variable              | Type | Default |
| ---------------------- | --------------------------------- | ------- | ------- |
| `insecure_skip_verify` | `BEYLA_OTEL_INSECURE_SKIP_VERIFY` | boolean | `false` |

Controls whether the OTEL client verifies the server's certificate chain and host name.
If set to `true`, the OTEL client accepts any certificate presented by the server
and any host name in that certificate. In this mode, TLS is susceptible to a man-in-the-middle
attacks. This option should be used only for testing and development purposes.

| YAML       | Environment variable                  | Type     | Default |
| ---------- | ------------------------ | -------- | ------- |
| `interval` | `BEYLA_METRICS_INTERVAL` | Duration | `5s`    |

Configures the intervening time between exports.

| YAML       | Environment variable          | Type            | Default                      |
|------------|-------------------------------|-----------------|------------------------------|
| `features` | `BEYLA_OTEL_METRICS_FEATURES` | list of strings | `["application"]` |

A list of metric groups which are allowed to be exported. Each group belongs to a different feature
of Beyla: application-level metrics or network metrics.

- If the list contains `application`, the Beyla OpenTelemetry exporter exports application-level metrics;
  but only if there is defined an OpenTelemetry endpoint, and Beyla was able to discover any
  process matching the entries in the `discovery` section.
- If the list contains `application_span`, the Beyla OpenTelemetry exporter exports application-level trace span metrics;
  but only if there is defined an OpenTelemetry endpoint, and Beyla was able to discover any
  process matching the entries in the `discovery` section.
- If the list contains `application_service_graph`, the Beyla OpenTelemetry exporter exports application-level service graph metrics;
  but only if there is defined an OpenTelemetry endpoint, and Beyla was able to discover any
  process matching the entries in the `discovery` section.
  For best experience with generating service graph metrics, use a DNS for service discovery and make sure the DNS names match
  the OpenTelemetry service names used in Beyla. In Kubernetes environments, the OpenTelemetry service name set by the service name
  discovery is the best choice for service graph metrics.
- If the list contains `application_process`, the Beyla OpenTelemetry exporter exports metrics about the processes that
  run the instrumented application.
- If the list contains `network`, the Beyla OpenTelemetry exporter exports network-level
  metrics; but only if there is an OpenTelemetry endpoint defined. For network-level metrics options visit the
  [network metrics]({{< relref "../network" >}}) configuration documentation.

| YAML                                  | Environment variable                             | Type     | Default |
|---------------------------------------|--------------------------------------------------|----------|---------|
| `allow_service_graph_self_references` | `BEYLA_OTEL_ALLOW_SERVICE_GRAPH_SELF_REFERENCES` | boolean  | `false` |

This option affects the behaviour of the generation of application-level service graph metrics, which can be enabled
by adding `application_service_graph` to the list of OpenTelemetry metric export features. By default, Beyla does not
report application-level service graph metrics which are considered to be self-referencing. For example, self-references
can be calls from local node metric scrape tools, or a service making an HTTP call to itself. Self-references
not useful for the purpose of showing service graphs, while at the same time they increase the cardinality and the
overall metric storage cost. To allow generation of application-level service graph metrics which also include
self-references, change this option value to `true`.

| YAML               | Environment variable                  | Type            | Default                      |
|--------------------|---------------------------------------|-----------------|------------------------------|
| `instrumentations` | `BEYLA_OTEL_METRICS_INSTRUMENTATIONS` | list of strings | `["*"]` |

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

| YAML      | Environment variable | Type   |
| --------- | ------- | ------ |
| `buckets` | (n/a)   | Object |

The `buckets` object allows overriding the bucket boundaries of diverse histograms. See
[Overriding histogram buckets](#overriding-histogram-buckets) section for more details.

| YAML                    | Environment variable                                       | Type     | Default                     |
|-------------------------|------------------------------------------------------------|----------|-----------------------------|
| `histogram_aggregation` | `OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION` | `string` | `explicit_bucket_histogram` |

Specifies the default aggregation to use for histogram instruments.

Accepted values are:

* `explicit_bucket_histogram` (default): use [Explicit Bucket Histogram Aggregation](https://opentelemetry.io/docs/specs/otel/metrics/sdk/#explicit-bucket-histogram-aggregation).
* `base2_exponential_bucket_histogram`: use [Base2 Exponential Bucket Histogram Aggregation](https://opentelemetry.io/docs/specs/otel/metrics/sdk/#base2-exponential-bucket-histogram-aggregation).

### Overriding histogram buckets

For both OpenTelemetry and Prometheus metrics exporters, you can override the histogram bucket
boundaries via a configuration file (see `buckets` YAML section of your metrics exporter configuration).

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

## OTEL traces exporter

> ℹ️ If you plan to use Beyla to send metrics to Grafana Cloud,
> consult the [Grafana Cloud OTEL exporter for metrics and traces](#using-the-grafana-cloud-otel-endpoint-to-ingest-metrics-and-traces)
> section for easier configuration.

YAML section `otel_traces_export`.

This component exports OpenTelemetry traces to a given endpoint. It will be enabled if
its `endpoint` attribute is set (either via an YAML configuration file or via environment variables).

In addition to the properties exposed in this section, this component implicitly supports
the environment variables from the [standard OTEL exporter configuration](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/).

| YAML       | Environment variable                                                                   | Type | Default |
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

| YAML               | Environment variable                  | Type            | Default                      |
|--------------------|---------------------------------------|-----------------|------------------------------|
| `instrumentations` | `BEYLA_OTEL_TRACES_INSTRUMENTATIONS`   | list of strings | `["*"]` |

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

| YAML       | Environment variable                                                                   | Type   | Default   |
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

| YAML   | Environment variable               | Type   | Default                 |
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

| YAML  | Environment variable                   | Type   | Default |
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

| YAML   | Environment variable                 | Type | Default |
| ------ | ----------------------- | ---- | ------- |
| `port` | `BEYLA_PROMETHEUS_PORT` | int  | (unset) |

Specifies the HTTP port for the Prometheus scrape endpoint. If unset or 0,
no Prometheus endpoint is open.

| YAML   | Environment variable                 | Type   | Default    |
| ------ | ----------------------- | ------ | ---------- |
| `path` | `BEYLA_PROMETHEUS_PATH` | string | `/metrics` |

Specifies the HTTP query path to fetch the list of Prometheus metrics.

| YAML  | Environment variable   | Type     | Default |
|-------|------------------------|----------|---------|
| `ttl` | `BEYLA_PROMETHEUS_TTL` | Duration | `5m`    |

The group of attributes for a metric instance is not reported anymore if the time since
the last update is greater than this Time-To-Leave (TTL) value.

The purpose of this value is to avoid reporting indefinitely finished application instances.

| YAML      | Environment variable | Type   |
| --------- | ------- | ------ |
| `buckets` | (n/a)   | Object |

The `buckets` object allows overriding the bucket boundaries of diverse histograms. See
[Overriding histogram buckets](#overriding-histogram-buckets) section for more details.

| YAML       | Environment variable        | Type            | Default                      |
|------------|-----------------------------|-----------------|------------------------------|
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

| YAML                                  | Environment variable                                   | Type     | Default |
|---------------------------------------|--------------------------------------------------------|----------|---------|
| `allow_service_graph_self_references` | `BEYLA_PROMETHEUS_ALLOW_SERVICE_GRAPH_SELF_REFERENCES` | boolean  | `false` |

This option affects the behaviour of the generation of application-level service graph metrics, which can be enabled
by adding `application_service_graph` to the list of Prometheus metric export features. By default, Beyla does not
report application-level service graph metrics which are considered to be self-referencing. For example, self-references
can be calls from local node metric scrape tools, or a service making an HTTP call to itself. Self-references
not useful for the purpose of showing service graphs, while at the same time they increase the cardinality and the
overall metric storage cost. To allow generation of application-level service graph metrics which also include
self-references, change this option value to `true`.


| YAML               | Environment variable                  | Type            | Default                      |
|--------------------|---------------------------------------|-----------------|------------------------------|
| `instrumentations` | `BEYLA_PROMETHEUS_INSTRUMENTATIONS`   | list of strings | `["*"]` |

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

## Using the Grafana Cloud OTEL endpoint to ingest metrics and traces

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

| YAML           | Environment variable                | Type     | Default  |
| -------------- | ---------------------- | -------- | -------- |
| `cloud_submit` | `GRAFANA_CLOUD_SUBMIT` | []string | `traces` |

Accepts a list of strings with the kind of data that will be submitted to the
OTLP endpoint. It accepts `metrics` and/or `traces` as values.

| YAML         | Environment variable              | Type   | Default |
| ------------ | -------------------- | ------ | ------- |
| `cloud_zone` | `GRAFANA_CLOUD_ZONE` | string | (unset) |

The cloud zone of your Grafana endpoint. This will be used to compose the
Grafana OTLP URL. For example, if the value is `prod-eu-west-0`, the
used OTLP URL will be `https://otlp-gateway-prod-eu-west-0.grafana.net/otlp`.

If any of the `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`
or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` variables are defined, they will
override the destination endpoint, so the `cloud_zone` configuration option
will be ignored.

| YAML                | Environment variable                     | Type   | Default |
| ------------------- | --------------------------- | ------ | ------- |
| `cloud_instance_id` | `GRAFANA_CLOUD_INSTANCE_ID` | string | (unset) |

Your Grafana user name. It is usually a number but it must be set as a
string inside the YAML file.

| YAML            | Environment variable                 | Type   | Default |
| --------------- | ----------------------- | ------ | ------- |
| `cloud_api_key` | `GRAFANA_CLOUD_API_KEY` | string | (unset) |

API key of your Grafana Cloud account.
