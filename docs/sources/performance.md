---
title: Beyla performance impact calculation
menuTitle: Performance impact calculation
description: Learn about overhead calculation and performance impact of Beyla.
weight: 24
keywords:
  - Beyla
  - eBPF
  - performance
  - overhead
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/performance/
---

# Beyla performance impact calculation

## Introduction

This document explains how we calculate the overhead of Beyla and the performance impact it has on your applications running in production.

To measure the performance overhead, we followed this methodology:
- Deploy Beyla as single-process in a local Kubernetes cluster using Kind and Helm chart.
- Deploy [OpenTelemetry Demo](https://opentelemetry.io/docs/demo/architecture/) to showcase a real-world application with multiple services interacting with each other.
- Measure performance with `application_process`, instrumenting Beyla itself to extract process-level metrics. In this case we're measuring the CPU and memory usage of the Beyla process.
- Each scenario is additive to the previous one, so we can measure the impact of each feature on the performance.
- Use Prometheus to collect metrics and Grafana to visualize them.

## Performance impact

The OpenTelemetry demo comes with a load generator that simulates traffic to the application. This script generates traffic, between 20 and 60 requests/s, being the `/api/products` the endpoint with more traffic. Since there are also requests to Redis, Kafka, and internal RPC calls, the total amount of requests on average is 75 requests/s.

Table below shows the performance impact of Beyla on the OpenTelemetry Demo application.

| Scenario | Memory usage | CPU usage | Notes |
|----------|--------------|-----------|-------|
| Baseline (Beyla self instrumented) | 75MB | 0.05% | Beyla instrumented itself with `application` and `application_process` features |
| Default (all OTEL demo apps instrumented) | 75MB* | 0.5% | Instrumenting the whole set OTEL demo apps causes a peak of 600mb initially, as we find and instrument the symbols of running applications, but then goes down to its normal levels of 75mb. The CPU usage increased 10x because it has to process the traffic of all the applications. |
| Default + Application monitoring enabled | 85MB | 1.2% | Beyla with `application_span` and `application_service_graph`. Memory and CPU usage increases and Beyla needs to generate more metrics (metric spans and graph metrics) from every request.|
| Default + debug mode | 95MB | 2% | Beyla with `log_level: debug`, `bpf_debug: true` and print traces to `stdout`. Memory and CPU usage increases as Beyla needs to generate more logs and debug information.|
| Default + Network enabled | 120MB | 1.2% | Beyla with `network` feature enabled. Memory and CPU usage increases as Beyla needs to generate more metrics from network traffic.|
| OpenTelemetry tracing enabled | 80MB* | 0.4% | Beyla generating traces instead of metrics. The  memory usage increases in bursts as it has to create batches of traces to send to the collector.|
| OpenTelemetry metrics enabled | 105MB | 1.5% | This is the same as _Default + Application monitoring enabled_ but using the OpenTelemetry metrics exporter.|

## eBPF programs overhead

The eBPF programs run in the kernel space and execute in the context of the application. The overhead of the eBPF programs is minimal because they're lightweight and efficient. By running in the kernel, they avoid the context-switching overhead associated with user-space programs. Additionally, eBPF programs use Just-In-Time (JIT) compilation, which further optimizes their performance.

To measure the latency, we used the `ebpf` feature of Beyla to collect the latency of the eBPF programs. the observed latency of all combined probes of Beyla running for 24 hours in the OpenTelemetry demo is around 40ms. This represents 500ns of latency per request, which is negligible.

## Further reading

* [Beyla performance calculation](https://grafana.com/media/pdf/beyla_performance_calculation.pdf). This document contains the raw data and graphs of the performance tests.