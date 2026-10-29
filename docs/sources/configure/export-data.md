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
| `features`<p>`BEYLA_OTEL_METRICS_FEATURES`</p>                                               | The list of metric groups Beyla exports data for, refer to [metrics export features](#metrics-export-features).                                                                                                                                                                                                                                                                                                                        | list of strings | `["application"]`           |
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

- `application`: Application RED metrics and HTTP body-size histograms
- `application_red`: Application RED metrics without HTTP body-size histograms
- `application_sizes`: HTTP request and response body-size histograms
- `application_span`: Application-level trace span metrics using legacy naming conventions.
  Deprecated: use `application_span_otel` instead. The name keeps working, but Beyla logs a deprecation warning at startup and the feature is removed in a future release
- `application_span_otel`: Application-level trace span metrics using OpenTelemetry naming conventions. Refer to [span metrics formats](#span-metrics-formats) for differences between `application_span` and `application_span_otel`
- `application_span_sizes`: Application-level request and response body size metrics for trace spans.
  Deprecated: there is no direct replacement. The closest equivalents are the `http.server.request.body.size` and `http.server.response.body.size` metrics
- `application_host`: Application-level host metrics for host based pricing
- `application_service_graph`: Application-level service graph metrics.
  It's recommended to use a DNS for service discovery and to ensure the DNS names match the OpenTelemetry service names Beyla uses.
  In Kubernetes environments, the OpenTelemetry service name set by the service name discovery is the best choice for service graph metrics.
- `application_service_graph_connection_info`: An opt-in presence gauge named
  `traces_service_graph_connection_info`. It is independent of service graph
  request and latency metrics, is not enabled by default, and is not included in
  `application`, `application_service_graph`, or `all`.

  Beyla sets the gauge to `1` for an observed client-to-destination edge when
  the client service and destination identities are available. A matching
  server span is not required. The gauge remains active for 15 minutes after the
  last observation.

  Enable it in the global `metrics.features` list:

  ```yaml
  metrics:
    features:
      - application_service_graph_connection_info
  prometheus_export:
    port: 8999
  ```

  This metric serves a similar topology-discovery purpose to [the Tempo
  connection information metric](/docs/tempo/latest/metrics-from-traces/service_graphs/#connection-information-metric),
  but Beyla derives it from observed client traffic. Beyla exports the metric
  directly; it does not require enabling the Tempo
  `service-graphs-connection-info` processor.
- `application_process`: Low-level process metrics (for example, CPU, memory, disk metrics) for the selected services
- `application_runtime`: Go, JVM, Node.js, Python, and .NET runtime metrics. Refer to [Application runtime metrics](#application-runtime-metrics) for the full list of exported metrics.
- `network`: Network-level metrics, refer to the [network metrics](/docs/beyla/latest/network/) configuration documentation to learn more
- `network_flow_packets`: Network packet counts. Enables `beyla.network.flow.packets` (`beyla_network_flow_packets_total` in Prometheus)
- `network_inter_zone`: Network inter-zone metrics, refer to the [network metrics](/docs/beyla/latest/network/) configuration documentation to learn more
- `stats`: All TCP statistics metrics, including the higher-frequency `stats_tcp_io` probes
- `stats_tcp_successful_connections`: Successful TCP connection counts
- `stats_tcp_failed_connections`: Failed TCP connection counts. Enables `beyla.stat.tcp.failed.connections` (`beyla_stat_tcp_failed_connections_total` in Prometheus)
- `stats_tcp_io`: Bytes sent and received at the TCP socket layer. Enables `beyla.stat.tcp.io` (`beyla_stat_tcp_io_bytes_total` in Prometheus)
- `stats_tcp_retransmits`: TCP retransmission counts. Enables `beyla.stat.tcp.retransmits` (`beyla_stat_tcp_retransmits_total` in Prometheus)
- `stats_tcp_rtt`: Smoothed TCP round-trip time. Enables the `beyla.stat.tcp.rtt` histogram (`beyla_stat_tcp_rtt_seconds` in Prometheus)

The `stats` feature enables every TCP statistics group. The `stats_tcp_io` probes run for every `tcp_sendmsg` and `tcp_cleanup_rbuf` call, so their overhead grows with TCP send and receive activity. If you don't need TCP I/O byte counts, select the lower-frequency TCP statistics individually instead of using `stats`.

### Successful TCP connections

Select `stats_tcp_successful_connections` to export `beyla.stat.tcp.successful.connections` (`beyla_stat_tcp_successful_connections_total` in Prometheus). The `stats` bundle includes this counter.

```yaml
metrics:
  features: ["application", "stats_tcp_successful_connections"]
```

The counter records successful TCP handshakes rather than application requests. The same feature is accepted in per-service and deprecated exporter feature lists. Use [attribute selection](../metrics-traces-attributes/#select-tcp-handshake-roles) to split connections by handshake role.

### Application runtime metrics

Enable `application_runtime` to collect runtime metrics for instrumented Go, Java, Node.js, Python, and .NET processes. It is disabled by default. Configure it globally or per service through [metrics features](#global-metrics-features).

Go and Python metrics use eBPF collection. Node.js metrics require the injected Node.js agent. JVM memory metrics use HotSpot USDT probes; the Java agent supplies class, thread, CPU, and GC duration metrics. .NET metrics use the runtime diagnostic socket and EventPipe.

**Go runtime metrics**

| Metric | Description |
| ------ | ----------- |
| `go.memory.limit` | Runtime memory limit configured via `GOMEMLIMIT` |
| `go.memory.gc.goal` | Heap size target for the next GC cycle |
| `go.memory.gc.cycles` | Cumulative count of completed GC cycles |
| `go.memory.gc.pause.duration` | Total time spent in GC stop-the-world pauses |
| `go.memory.used` | Memory in use by the Go runtime |
| `go.memory.allocated` | Cumulative bytes allocated by the runtime |
| `go.memory.allocations` | Cumulative number of heap object allocations |
| `go.cpu.time` | Cumulative CPU time consumed by the Go process |
| `go.goroutine.count` | Number of live goroutines |
| `go.processor.limit` | `GOMAXPROCS` value (logical CPU limit) |
| `go.config.gogc` | Current GC target percentage (`GOGC`) |
| `go.schedule.duration` | Time goroutines spend waiting on the scheduler run queue |

**JVM runtime metrics**

JVM memory pool metrics use eBPF USDT probes on `libjvm.so` (`hotspot:mem__pool__gc__begin` and `hotspot:mem__pool__gc__end`). They remain available when `javaagent.enabled` is `false`. The other JVM metrics require the Java agent.

| Metric | Description |
| ------ | ----------- |
| `jvm.memory.used` | Current bytes used in the JVM memory pool |
| `jvm.memory.committed` | Bytes committed (reserved) for the JVM memory pool |
| `jvm.memory.limit` | Maximum bytes the memory pool can use |
| `jvm.memory.used_after_last_gc` | Bytes used in the pool immediately after the last GC cycle |
| `jvm.class.loaded` | Classes loaded |
| `jvm.class.unloaded` | Classes unloaded |
| `jvm.class.count` | Current loaded classes |
| `jvm.thread.count` | Live platform threads, split by daemon status |
| `jvm.cpu.time` | Process CPU time in seconds |
| `jvm.cpu.count` | Available processors |
| `jvm.cpu.recent_utilization` | Recent process CPU utilization |
| `jvm.gc.duration` | GC action duration in seconds |

JVM memory metrics carry the attributes `jvm.memory.type` (for example, `heap`, `non_heap`) and `jvm.memory.pool.name` (for example, `G1 Eden Space`).

To control how frequently JVM GC events are sampled, refer to [JVM runtime metrics](#jvm-runtime-metrics).

**Node.js runtime metrics**

Set `nodejs.enabled` to `true` and enable `application_runtime` to collect these metrics. Disabling the agent disables their collection.

| Metric | Description |
| --- | --- |
| `nodejs.eventloop.time` | Active and idle event loop time in seconds |
| `nodejs.eventloop.utilization` | Event loop utilization |
| `nodejs.eventloop.delay.min` | Minimum event loop delay in seconds |
| `nodejs.eventloop.delay.max` | Maximum event loop delay in seconds |
| `nodejs.eventloop.delay.mean` | Mean event loop delay in seconds |
| `nodejs.eventloop.delay.stddev` | Standard deviation of event loop delay in seconds |
| `nodejs.eventloop.delay.p50` | 50th percentile event loop delay in seconds |
| `nodejs.eventloop.delay.p90` | 90th percentile event loop delay in seconds |
| `nodejs.eventloop.delay.p99` | 99th percentile event loop delay in seconds |
| `v8js.gc.duration` | GC duration in seconds |
| `v8js.memory.heap.limit` | Heap limit in bytes, per space |
| `v8js.memory.heap.used` | Used heap bytes, per space |
| `v8js.memory.heap.space.available_size` | Available bytes per heap space |
| `v8js.memory.heap.space.physical_size` | Committed bytes per heap space |
| `v8js.resource.active` | Active resources, grouped by resource type |

**Python runtime metrics**

| Metric | Description |
| --- | --- |
| `cpython.gc.collections` | GC collections by generation |
| `cpython.gc.collected_objects` | Collected objects by generation |
| `cpython.gc.uncollectable_objects` | Uncollectable objects by generation |

**.NET runtime metrics**

| Metric | Description |
| --- | --- |
| `dotnet.process.cpu.count` | Available processors |
| `dotnet.process.cpu.time` | Process CPU time in seconds, split by user and system mode |
| `dotnet.process.memory.working_set` | Physical memory mapped to the process, in bytes |
| `dotnet.gc.collections` | Collections since the collector baseline, exclusive per generation |
| `dotnet.gc.heap.total_allocated` | Allocated heap bytes observed by the collector |
| `dotnet.gc.last_collection.heap.size` | Heap size in bytes at the latest collection, per generation |
| `dotnet.gc.last_collection.heap.fragmentation.size` | Heap fragmentation in bytes at the latest collection, per generation |
| `dotnet.gc.last_collection.memory.committed_size` | Committed GC memory in bytes at the latest collection |
| `dotnet.gc.pause.time` | GC pause time in seconds observed by the collector |
| `dotnet.jit.compiled_il.size` | Compiled IL bytes |
| `dotnet.jit.compiled_methods` | Compiled methods |
| `dotnet.jit.compilation.time` | JIT compilation time in seconds observed by the collector |
| `dotnet.thread_pool.thread.count` | Current thread-pool threads |
| `dotnet.thread_pool.work_item.count` | Completed thread-pool work items observed by the collector |
| `dotnet.thread_pool.queue.length` | Queued thread-pool work items |
| `dotnet.monitor.lock_contentions` | Lock contentions observed by the collector |
| `dotnet.exceptions` | Exceptions by error type observed by the collector |
| `dotnet.timer.count` | Active timers |
| `dotnet.assembly.count` | Loaded assemblies |

Refer to [.NET runtime collection](#net-runtime-collection) for prerequisites and timing controls, and [runtime GC buckets](../metrics-histograms/#runtime-garbage-collection-buckets) for JVM and V8 histograms.

### Span metrics formats

Beyla provides two formats for span metrics:

- `application_span`: Legacy format using the metric names `traces_spanmetrics_latency` and `traces_spanmetrics_calls_total`. Deprecated: use `application_span_otel` instead
- `application_span_otel`: OpenTelemetry-compliant format using the metric names `traces_span_metrics_duration_seconds` and `traces_span_metrics_calls_total`

You can only enable one span metrics format at a time. If you specify both `application_span` and `application_span_otel` in the `features` list, Beyla returns a configuration error. The same applies when one format comes from the top-level `metrics` section and the other from a per-service `discovery` `metrics.features` section, because the exported metric names are selected from the combination of both.

If you select the formats implicitly with `all` or `*`, Beyla resolves the conflict automatically in favor of `application_span_otel` and logs a warning. This resolution also applies to per-service `metrics.features` sections, so a single service requesting `all` doesn't move every service back to the legacy names.

### Metrics instrumentation

The list of instrumentation areas Beyla can collection data from:

- `*`: all instrumentation, if `*` is present Beyla ignores other values
- `aerospike`: Aerospike database metrics
- `amqp`: AMQP message queue metrics
- `couchbase`: Couchbase database metrics
- `dns`: DNS request metrics
- `genai`: Generative AI metrics
- `gpu`: GPU operation metrics
- `http`: HTTP/HTTPS/HTTP2 application metrics
- `grpc`: gRPC application metrics
- `kafka`: Kafka client/server message queue metrics
- `memcached`: Memcached database metrics
- `mongo`: MongoDB client/server database metrics
- `mqtt`: MQTT message queue metrics
- `nats`: NATS message queue metrics
- `redis`: Redis client/server database metrics
- `sql`: SQL database client call metrics
- `sunrpc`: SunRPC call metrics

For example, setting the `instrumentations` option to: `http,grpc` enables the collection of `HTTP/HTTPS/HTTP2` and `gRPC` application metrics, and disables other instrumentation.

## OpenTelemetry traces exporter component

YAML section: `otel_traces_export`

You can configure the component under the `otel_traces_export` section of your YAML configuration or via environment variables.

In addition to the configuration documented in this article, the component supports the environment variables from the [standard OpenTelemetry exporter configuration](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/).

```yaml
otel_traces_export:
  endpoint: http://jaeger:4317
  protocol: grpc
  instrumentations: ["http", "sql"]
```

| YAML<p>environment variable</p>                                                       | Description                                                                                                                                                                                                                                                                                               | Type            | Default                  |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | ------------------------ |
| `endpoint`<p>`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`<p>`OTEL_EXPORTER_OTLP_ENDPOINT`</p> | The endpoint Beyla sends traces to. When using `OTEL_EXPORTER_OTLP_ENDPOINT`, Beyla follows the OpenTelemetry standard and automatically adds `/v1/traces` path to the URL. If you don't want this to happen, use the traces specific setting.                                                            | URL             |                          |
| `protocol`<p>`OTEL_EXPORTER_OTLP_TRACES_PROTOCOL`<p>`OTEL_EXPORTER_OTLP_PROTOCOL`</p> | The protocol transport/encoding of the OpenTelemetry endpoint, refer to [traces export protocol](#traces-export-protocol). [Accepted values](https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/#otel_exporter_otlp_protocol) `http/json`, `http/protobuf`, and `grpc`. | string          | Inferred from port usage |
| `insecure_skip_verify`<p>`BEYLA_OTEL_INSECURE_SKIP_VERIFY`</p>                        | If `true`, Beyla skips verifying and accepts any server certificate. Only override this setting for non-production environments.                                                                                                                                                                          | boolean         | `false`                  |
| `instrumentations`<p>`BEYLA_OTEL_TRACES_INSTRUMENTATIONS`</p>                         | The list of instrumentation Beyla collects data for, refer to [traces instrumentation](#traces-instrumentation) section.                                                                                                                                                                                  | list of strings | `["http", "grpc", "sql", "redis", "kafka", "mqtt", "nats", "amqp", "mongo", "couchbase", "memcached", "sunrpc", "aerospike"]` |

### Traces export protocol

If you don't set a protocol Beyla sets the protocol as follows:

- `grpc`: if the port ends in `4317`, for example `4317`, `14317`, or `24317`.
- `http/protobuf`: if the port ends in `4318`, for example `4318`, `14318`, or `24318`.

### Traces export compression

Set `otel_traces_export.compression` to `gzip` to compress OTLP trace payloads, or `none` to send them uncompressed. The default is uncompressed. Gzip reduces transfer size at the cost of compression CPU time and is supported by the HTTP and gRPC exporters.

```yaml
otel_traces_export:
  endpoint: http://collector:4317
  protocol: grpc
  compression: gzip
```

`OTEL_EXPORTER_OTLP_TRACES_COMPRESSION` sets the traces-specific value and overrides YAML. When no traces-specific value is set, `OTEL_EXPORTER_OTLP_COMPRESSION` supplies the shared value. Both accept `none` and `gzip`.

For example, compress traces while keeping the shared setting uncompressed:

```sh
export OTEL_EXPORTER_OTLP_COMPRESSION=none
export OTEL_EXPORTER_OTLP_TRACES_COMPRESSION=gzip
```

### Traces instrumentation

The list of instrumentation areas Beyla can collection data from:

- `*`: all instrumentation, if `*` is present Beyla ignores other values
- `aerospike`: Aerospike database traces
- `amqp`: AMQP message queue traces
- `couchbase`: Couchbase database traces
- `dns`: DNS request traces
- `genai`: Generative AI traces
- `gpu`: GPU operation traces
- `http`: HTTP/HTTPS/HTTP2 application traces
- `grpc`: gRPC application traces
- `kafka`: Kafka client/server message queue traces
- `memcached`: Memcached database traces
- `mongo`: MongoDB client/server database traces
- `mqtt`: MQTT message queue traces
- `nats`: NATS message queue traces
- `redis`: Redis client/server database traces
- `sql`: SQL database client call traces
- `sunrpc`: SunRPC call traces

For example, setting the `instrumentations` option to: `http,grpc` enables the collection of `HTTP/HTTPS/HTTP2` and `gRPC` application traces, and disables other instrumentation.

**Note**: By default, Beyla enables all supported trace instrumentations except `dns`, `genai`, and `gpu`. You can explicitly enable these instrumentations if needed.

## Prometheus exporter component

YAML section: `prometheus_export`

You can configure the component under the `prometheus_export` section of your YAML configuration or via environment variables.
This component opens an HTTP endpoint in the auto-instrumentation tool that allows any external scraper to pull metrics in Prometheus format. It is enabled if the `port` property is set.

{{< admonition type="note" >}}
Prometheus scrapers override the `instance` and `job` labels by default. To preserve the per-process instance identifiers set by Beyla, configure your scraper with `honor_labels: true`. See the [Prometheus documentation](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config) or [Alloy `prometheus.scrape` documentation](/docs/alloy/latest/reference/components/prometheus/prometheus.scrape/).
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

- `application`: Application RED metrics and HTTP body-size histograms
- `application_red`: Application RED metrics without HTTP body-size histograms
- `application_sizes`: HTTP request and response body-size histograms
- `application_span`: Application-level trace span metrics
- `application_host` Application-level host metrics for host based pricing
- `application_service_graph`: Application-level service graph metrics.
  It's recommended to use a DNS for service discovery and to ensure the DNS names match the OpenTelemetry service names Beyla uses.
  In Kubernetes environments, the OpenTelemetry service name set by the service name discovery is the best choice for service graph metrics.
- `application_process`: Low-level process metrics (for example, CPU, memory, disk metrics) for the selected services
- `application_runtime`: Go, JVM, Node.js, Python, and .NET runtime metrics. Refer to [Application runtime metrics](#application-runtime-metrics) for the full list of exported metrics.
- `network`: Network-level metrics, refer to the [network metrics](/docs/beyla/latest/network/) configuration documentation to learn more
- `network_flow_packets`: Network packet counts
- `network_inter_zone`: Network inter-zone metrics, refer to the [network metrics](/docs/beyla/latest/network/) configuration documentation to learn more
- `stats`: All TCP statistics metrics
- `stats_tcp_successful_connections`: Successful TCP connection counts
- `stats_tcp_failed_connections`: Failed TCP connection counts
- `stats_tcp_io`: Bytes sent and received at the TCP socket layer
- `stats_tcp_retransmits`: TCP retransmission counts
- `stats_tcp_rtt`: Smoothed TCP round-trip time

The `prometheus_export.features` option is deprecated. Use the global [`metrics.features`](#global-metrics-features) option for new configurations.

### Prometheus instrumentation

The list of instrumentation areas Beyla can collection data from:

- `*`: all instrumentation, if `*` is present Beyla ignores other values
- `aerospike`: Aerospike database metrics
- `amqp`: AMQP message queue metrics
- `couchbase`: Couchbase database metrics
- `dns`: DNS request metrics
- `genai`: Generative AI metrics
- `gpu`: GPU operation metrics
- `http`: HTTP/HTTPS/HTTP2 application metrics
- `grpc`: gRPC application metrics
- `kafka`: Kafka client/server message queue metrics
- `memcached`: Memcached database metrics
- `mongo`: MongoDB client/server database metrics
- `mqtt`: MQTT message queue metrics
- `nats`: NATS message queue metrics
- `redis`: Redis client/server database metrics
- `sql`: SQL database client call metrics
- `sunrpc`: SunRPC call metrics

For example, setting the `instrumentations` option to: `http,grpc` enables the collection of `HTTP/HTTPS/HTTP2` and `gRPC` application metrics, and disables other instrumentation.

## Global metrics features

You can set the default `features` list for all exporters at once using the global `metrics` configuration block, rather than repeating it under each exporter. Deprecated exporter feature settings can override this global setting for both exporters.

The `metrics.features` option (environment variable: `BEYLA_METRICS_FEATURES`, also accepted as `OTEL_EBPF_METRICS_FEATURES`) accepts a list of feature group names. The default is `["application"]`.

You can also override the global features for one discovered service with `discovery.instrument[].metrics.features`. The deprecated exporter-specific options also override the global list. When the OTLP metrics endpoint is enabled and `otel_metrics_export.features` is configured, that list wins. Otherwise, an enabled Prometheus endpoint with `prometheus_export.features` supplies the list. This normalized list applies to both exporters. Use `metrics.features` for new configurations.

`application` enables both `application_red` and `application_sizes`. The size group exports `http.server.request.body.size`, `http.server.response.body.size`, `http.client.request.body.size`, and `http.client.response.body.size`. To collect RED metrics without these four histograms:

```yaml
metrics:
  features: ["application_red"]
```

To collect both groups explicitly:

```yaml
metrics:
  features: ["application_red", "application_sizes"]
```

The same values are accepted in `discovery.instrument[].metrics.features` and the deprecated exporter lists. Per-service lists replace the global selection for the matching process. The exporter environment variables are `BEYLA_OTEL_METRICS_FEATURES` and `BEYLA_PROMETHEUS_FEATURES`.

To collect application and runtime metrics for all instrumented services:

```yaml
metrics:
  features: ["application", "application_runtime"]
```

To enable selected network and TCP statistics globally for all processes:

```yaml
metrics:
  features:
    - application
    - network_flow_packets
    - stats_tcp_failed_connections
    - stats_tcp_retransmits
    - stats_tcp_rtt
```

To enable `application_runtime` only for a specific process, use the per-service `metrics.features` override in service discovery:

```yaml
discovery:
  instrument:
    - name: my-java-service
      exe_path: ".*/java"
      metrics:
        features:
          - application_runtime
```

## JVM runtime metrics

When `application_runtime` is enabled for Java services, Beyla collects memory pool metrics from HotSpot USDT probes and other JVM metrics through the Java agent. Set `javaagent.enabled` to `false` to disable agent collection while keeping HotSpot memory metrics.

The sampling interval controls HotSpot memory event sampling and Java agent class, thread, and CPU snapshots. It limits collection frequency for JVMs with frequent GC events.

| YAML<p>environment variable</p> | Description | Type | Default |
| -------------------------------- | ----------- | ---- | ------- |
| `jvm_runtime_metrics.sampling_interval`<p>`OBI_JVM_RUNTIME_METRICS_SAMPLING_INTERVAL`</p> | Minimum time between successive JVM runtime metric samples. Must be greater than `0`. | Duration | `1s` |

Example:

```yaml
jvm_runtime_metrics:
  sampling_interval: 1s
```

## .NET runtime collection

Enable `application_runtime` for the target service. Beyla connects to the .NET diagnostic socket in the process's temporary directory, using `TMPDIR` when configured or `/tmp` otherwise. Diagnostics must be enabled and the socket must be accessible to Beyla.

| YAML option<p>Environment variable</p> | Description | Type | Default |
| --- | --- | --- | --- |
| `dotnet_runtime_metrics.sampling_interval`<p>`OBI_DOTNET_RUNTIME_METRICS_SAMPLING_INTERVAL`</p> | Requested `System.Runtime` EventCounter interval and delay before reconnecting after a collection session ends. Must be greater than `0`. | Duration | `1s` |
| `dotnet_runtime_metrics.timeout`<p>`OBI_DOTNET_RUNTIME_METRICS_TIMEOUT`</p> | Timeout for diagnostic IPC setup and EventPipe session shutdown. Must be greater than `0`. | Duration | `10s` |

For example:

```yaml
metrics:
  features: ["application", "application_runtime"]
dotnet_runtime_metrics:
  sampling_interval: 2s
  timeout: 15s
```

Processes with the same service identity contribute to shared runtime series. Beyla tracks counter baselines per process; exported counters describe the observations available to the collector.
