---
title: Beyla exported metrics
menuTitle: Exported metrics
description: Learn about the HTTP/gRPC metrics Beyla can export.
weight: 4
keywords:
  - Beyla
  - eBPF
  - metrics
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/metrics/
---

# Beyla exported metrics

The following table describes the exported metrics in both OpenTelemetry and Prometheus format.

| Family      | Name (OTEL)                     | Name (Prometheus)                      | Type      | Unit    | Description                                                                      |
|-------------|---------------------------------|----------------------------------------|-----------|---------|----------------------------------------------------------------------------------|
| Application | `http.client.request.duration`  | `http_client_request_duration_seconds` | Histogram | seconds | Duration of HTTP service calls from the client side                              |
| Application | `http.client.request.body.size` | `http_client_request_body_size_bytes`  | Histogram | bytes   | Size of the HTTP request body as sent by the client                              |
| Application | `http.server.request.duration`  | `http_server_request_duration_seconds` | Histogram | seconds | Duration of HTTP service calls from the server side                              |
| Application | `http.server.request.body.size` | `http_server_request_body_size_bytes`  | Histogram | bytes   | Size of the HTTP request body as received at the server side                     |
| Application | `rpc.client.duration`           | `rpc_client_duration_seconds`          | Histogram | seconds | Duration of GRPC service calls from the client side                              |
| Application | `rpc.server.duration`           | `rpc_server_duration_seconds`          | Histogram | seconds | Duration of RPC service calls from the server side                               |
| Application | `sql.client.duration`           | `sql_client_duration_seconds`          | Histogram | seconds | Duration of SQL client operations (Experimental)                                 |
| Application | `redis.client.duration`         | `redis_client_duration_seconds`        | Histogram | seconds | Duration of Redis client operations (Experimental)                               |
| Application | `messaging.publish.duration`    | `messaging_publish_duration`        | Histogram | seconds | Duration of Messaging (Kafka) publish operations (Experimental)                               |
| Application | `messaging.process.duration`    | `messaging_process_duration`        | Histogram | seconds | Duration of Messaging (Kafka) process operations (Experimental)                               |
| Network     | `beyla.network.flow.bytes`      | `beyla_network_flow_bytes`             | Counter   | bytes   | Bytes submitted from a source network endpoint to a destination network endpoint |

Beyla can also export [Span metrics](/docs/tempo/latest/metrics-generator/span_metrics/) and
[Service graph metrics](/docs/tempo/latest/metrics-generator/service-graph-view/), which you can enable via the
[features]({{< relref "./configure/options.md" >}}) configuration option.

## Attributes of Beyla metrics

For the sake of brevity, the metrics and attributes in this list use the OTEL `dot.notation`. When using the Prometheus exporter, the metrics use `underscore_notation`.

In order to configure which attributes to show or which attributes to hide, check the `attributes`->`select` section in the [configuration documentation]({{< relref "./configure/options.md" >}}).

| Metrics                        | Name                        | Default                                       |
|--------------------------------|-----------------------------|-----------------------------------------------|
| Application (all)              | `http.request.method`       | shown                                         |
| Application (all)              | `http.response.status_code` | shown                                         |
| Application (all)              | `http.route`                | shown if `routes` configuration section exists  |
| Application (all)              | `k8s.daemonset.name`        | shown if `attributes.kubernetes.enable`       |
| Application (all)              | `k8s.deployment.name`       | shown if `attributes.kubernetes.enable`       |
| Application (all)              | `k8s.namespace.name`        | shown if `attributes.kubernetes.enable`       |
| Application (all)              | `k8s.node.name`             | shown if `attributes.kubernetes.enable`       |
| Application (all)              | `k8s.pod.name`              | shown if `attributes.kubernetes.enable`       |
| Application (all)              | `k8s.pod.start_time`        | shown if `attributes.kubernetes.enable`       |
| Application (all)              | `k8s.pod.uid`               | shown if `attributes.kubernetes.enable`       |
| Application (all)              | `k8s.replicaset.name`       | shown if `attributes.kubernetes.enable`       |
| Application (all)              | `k8s.statefulset.name`      | shown if `attributes.kubernetes.enable`       |
| Application (all)              | `k8s.cluster.name`          | shown if `attributes.kubernetes.enable`       |
| Application (all)              | `service.name`              | shown                                         | 
| Application (all)              | `service.namespace`         | shown                                         | 
| Application (all)              | `target.instance`           | shown                                         |
| Application (all)              | `url.path`                  | hidden                                        |
| Application (client)           | `server.address`            | hidden                                        |
| Application (client)           | `server.port`               | hidden                                        |
| Application `rpc.*`            | `rpc.grpc.status_code`      | shown                                         |
| Application `rpc.*`            | `rpc.method`                | shown                                         |
| Application `rpc.*`            | `rpc.system`                | shown                                         |
| Application (server)           | `client.address`            | hidden                                        |
| `beyla.network.flow.bytes`     | `beyla.ip`                  | hidden                                        |
| `db.client.operation.duration` | `db.operation.name`         | shown                                         |
| `db.client.operation.duration` | `db.collection.name`        | hidden                                        |
| `messaging.publish.duration`   | `messaging.system`          | shown                                         |
| `messaging.publish.duration`   | `messaging.destination.name`| shown                                         |
| `messaging.process.duration`   | `messaging.system`          | shown                                         |
| `messaging.process.duration`   | `messaging.destination.name`| shown                                         |
| `beyla.network.flow.bytes`     | `direction`                 | hidden                                        |
| `beyla.network.flow.bytes`     | `dst.address`               | hidden                                        |
| `beyla.network.flow.bytes`     | `dst.cidr`                  | shown if the `cidrs` configuration section exists |
| `beyla.network.flow.bytes`     | `dst.name`                  | hidden                                        |
| `beyla.network.flow.bytes`     | `dst.port`                  | hidden                                        |
| `beyla.network.flow.bytes`     | `iface`                     | hidden                                        |
| `beyla.network.flow.bytes`     | `k8s.cluster.name`          | shown if `attributes.kubernetes.enable`       |
| `beyla.network.flow.bytes`     | `k8s.dst.name`              | hidden                                        | 
| `beyla.network.flow.bytes`     | `k8s.dst.namespace`         | shown if `attributes.kubernetes.enable`       | 
| `beyla.network.flow.bytes`     | `k8s.dst.node.ip`           | hidden                                        |
| `beyla.network.flow.bytes`     | `k8s.dst.node.name`         | hidden                                        |
| `beyla.network.flow.bytes`     | `k8s.dst.owner.type`        | hidden                                        | 
| `beyla.network.flow.bytes`     | `k8s.dst.type`              | hidden                                        |
| `beyla.network.flow.bytes`     | `k8s.dst.owner.name`        | shown if `attributes.kubernetes.enable`       | 
| `beyla.network.flow.bytes`     | `k8s.src.name`              | hidden                                        | 
| `beyla.network.flow.bytes`     | `k8s.src.namespace`         | shown if `attributes.kubernetes.enable`       | 
| `beyla.network.flow.bytes`     | `k8s.src.node.ip`           | hidden                                        |
| `beyla.network.flow.bytes`     | `k8s.src.owner.name`        | shown if `attributes.kubernetes.enable`       |
| `beyla.network.flow.bytes`     | `k8s.src.owner.type`        | hidden                                        |
| `beyla.network.flow.bytes`     | `k8s.src.type`              | hidden                                        | 
| `beyla.network.flow.bytes`     | `src.address`               | hidden                                        |
| `beyla.network.flow.bytes`     | `src.cidr`                  | shown if the `cidrs` configuration section exists |
| `beyla.network.flow.bytes`     | `src.name`                  | hidden                                        |
| `beyla.network.flow.bytes`     | `src.port`                  | hidden                                        |
| `beyla.network.flow.bytes`     | `transport`                 | hidden                                        |
| Traces (SQL, Redis)            | `db.query.text`             | hidden                                        |

## Internal metrics

Beyla can be [configured to report internal metrics]({{< relref "./configure/options.md#internal-metrics-reporter" >}}) in Prometheus Format.

| Name                                  | Type        | Description                                                                              |
| ------------------------------------- | ----------- | ---------------------------------------------------------------------------------------- |
| `beyla_ebpf_tracer_flushes`           | Histogram   | Length of the groups of traces flushed from the eBPF tracer to the next pipeline stage   |
| `beyla_otel_metric_exports_total`     | Counter     | Length of the metric batches submitted to the remote OTEL collector                      |
| `beyla_otel_metric_export_errors_total` | CounterVec | Error count on each failed OTEL metric export, by error type                             |
| `beyla_otel_trace_exports_total`      | Counter     | Length of the trace batches submitted to the remote OTEL collector                       |
| `beyla_otel_trace_export_errors_total` | CounterVec | Error count on each failed OTEL trace export, by error type                              |
| `beyla_prometheus_http_requests_total` | CounterVec | Number of requests towards the Prometheus Scrape endpoint, faceted by HTTP port and path |
| `beyla_instrumented_processes`        | GaugeVec    | Instrumented processes by Beyla, with process name                                       |
| `beyla_build_info`                    | GaugeVec    | Version information of the Beyla binary, including the build time and commit hash        |
