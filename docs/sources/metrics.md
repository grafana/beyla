---
title: Beyla exported metrics
menuTitle: Exported metrics
description: Learn about which HTTP/gRPC metrics can be exported by Grafana's application auto-instrumentation tool.
weight: 4
---

# Beyla exported metrics

## Application instrumentation metrics

The following table describes the exported metrics in both OpenTelemetry and Prometheus format.

| Name (OTEL)                | Name (Prometheus)                | Type      | Unit    | Description                                                  |
| -------------------------- | -------------------------------- | --------- | ------- | ------------------------------------------------------------ |
| `http.client.duration`     | `http_client_duration_seconds`   | Histogram | seconds | Duration of HTTP service calls from the client side          |
| `http.client.request.size` | `http_client_request_size_bytes` | Histogram | bytes   | Size of the HTTP request body as sent by the client          |
| `http.server.duration`     | `http_server_duration_seconds`   | Histogram | seconds | Duration of HTTP service calls from the server side          |
| `http.server.request.size` | `http_server_request_size_bytes` | Histogram | bytes   | Size of the HTTP request body as received at the server side |
| `rpc.client.duration`      | `rpc_client_duration_seconds`    | Histogram | seconds | Duration of GRPC service calls from the client side          |
| `rpc.server.duration`      | `rpc_server_duration_seconds`    | Histogram | seconds | Duration of RCP service calls from the server side           |

## Internal metrics

Additionally, the eBPF auto-instrument tool can be [configured to report internal metrics]({{< relref "./configure/options.md#internal-metrics-reporter" >}}) in Prometheus Format.

| Name                        | Type       | Description                                                                              |
| --------------------------- | ---------- | ---------------------------------------------------------------------------------------- |
| `ebpf_tracer_flushes`       | Histogram  | Length of the groups of traces flushed from the eBPF tracer to the next pipeline stage   |
| `otel_metric_exports`       | Counter    | Length of the metric batches submitted to the remote OTEL collector                      |
| `otel_metric_export_errors` | CounterVec | Error count on each failed OTEL metric export, by error type                             |
| `otel_trace_exports`        | Counter    | Length of the trace batches submitted to the remote OTEL collector                       |
| `otel_trace_export_errors`  | CounterVec | Error count on each failed OTEL trace export, by error type                              |
| `prometheus_http_requests`  | CounterVec | Number of requests towards the Prometheus Scrape endpoint, faceted by HTTP port and path |
