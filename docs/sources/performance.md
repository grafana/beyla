---
title: Beyla performance overhead
menuTitle: Performance overhead
description: Beyla runs alongside your applications and has a minimal impact on performance. Find out about the methodology we used to measure the performance overhead.

weight: 24
keywords:
  - Beyla
  - eBPF
  - performance
---

# Beyla performance overhead

Beyla runs alongside your applications and has a minimal impact on performance.
We use the following methodology to measure the performance overhead:

- Deploy Beyla as single-process in a local Kubernetes cluster using Kind and Helm chart
- Deploy [OpenTelemetry Demo](https://opentelemetry.io/docs/demo/architecture/) to showcase a real-world application with multiple services interacting with each other
- Measure performance with `application_process`, instrumenting Beyla to extract process-level metrics and measure CPU and memory usage
- Each scenario is additive to the previous one, so we can measure the impact of each feature on the performance
- Use Prometheus to collect metrics and Grafana to visualize them

## Performance impact

The OpenTelemetry demo comes with a load generator that simulates traffic to the application.
This script generates between 20 and 60 requests/s to the `/api/products` endpoint which can call Redis, Kafka, and internal RPC calls.
The total amount of requests is on average 75 requests/s.

Table below shows the performance impact of Beyla on the OpenTelemetry Demo application.

| Scenario                                 | Memory usage | CPU usage | Notes                                                                                                                                                                                                                                                                                         |
| ---------------------------------------- | ------------ | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Baseline: Beyla self instrumented        | 75MB         | 0.05%     | Beyla instrumenting itself with `application` and `application_process` features                                                                                                                                                                                                              |
| Default: all OTEL demo apps instrumented | 75MB*        | 0.5%      | Instrumenting all the OpenTelemetry demo applications initially causes a peak of 600mb, as we find and instrument the symbols of running applications, and goes down to its normal levels of 75mb. The CPU usage increased 10x because it has to process the traffic of all the applications. |
| Default + application monitoring enabled | 85MB         | 1.2%      | Beyla with `application_span` and `application_service_graph`. Memory and CPU usage increases and Beyla needs to generate more metrics (metric spans and graph metrics) for every request.                                                                                                    |
| Default + debug mode                     | 95MB         | 2%        | Beyla with `log_level: debug`, `bpf_debug: true`, and printing traces to `stdout`. Memory and CPU usage increases as Beyla needs to generate more logs and debug information.                                                                                                                 |
| Default + network enabled                | 120MB        | 1.2%      | Beyla with `network` feature enabled. Memory and CPU usage increases as Beyla needs to generate more metrics from network traffic.                                                                                                                                                            |
| OpenTelemetry metrics enabled            | 105MB        | 1.5%      | This is the same as *Default + application monitoring enabled* but using the OpenTelemetry metrics exporter.                                                                                                                                                                                  |
| OpenTelemetry tracing enabled            | 80MB*        | 0.4%      | Beyla generating traces instead of metrics. The memory usage increases in bursts as it has to create batches of traces to send to the collector.                                                                                                                                              |

## eBPF programs overhead

eBPF programs run in the kernel space and execute in the context of the application.
The overhead of the eBPF programs is minimal because they're lightweight and efficient.
By running in the kernel, they avoid the context-switching overhead associated with user-space programs.
Additionally, eBPF programs use Just-In-Time (JIT) compilation, which further optimizes their performance.

To measure latency, we used the `ebpf` feature of Beyla to collect the latency of the eBPF programs.
The observed latency of all combined probes of Beyla running for 24 hours in the OpenTelemetry demo is around 40ms.
This represents 500ns of latency per request, which is negligible.

## Raw data

You can access the raw data we used to analyze the performance in [beyla_performance_calculation.pdf](/media/pdf/beyla_performance_calculation.pdf).
