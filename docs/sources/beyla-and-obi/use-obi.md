---
title: Use OpenTelemetry eBPF Instrumentation with Grafana
menuTitle: Use OBI with Grafana
description: Configure OpenTelemetry eBPF Instrumentation (OBI) for Grafana Cloud Application Observability and Knowledge Graph, and use OpenTelemetry projects for capabilities that Grafana Beyla includes.
weight: 200
aliases:
  - ../setup/use-obi/ # /docs/beyla/<BEYLA_VERSION>/setup/use-obi/
keywords:
  - Beyla
  - eBPF
  - OpenTelemetry eBPF Instrumentation
  - OBI
---

# Use OpenTelemetry eBPF Instrumentation with Grafana

OpenTelemetry eBPF Instrumentation (OBI) works with the Grafana Cloud OTLP endpoint, and with any OpenTelemetry Collector or Prometheus-compatible backend.
This page shows how to configure OBI for Grafana Cloud, and how to use other OpenTelemetry projects for capabilities that Grafana Beyla includes.
To compare Beyla and OBI, refer to [Compare Beyla and OpenTelemetry eBPF Instrumentation][compare-obi].

[compare-obi]: ../compare/

## Configure OBI for Application Observability and Knowledge Graph

A base OBI installation provides basic functionality in Grafana Cloud
[Application Observability][application-observability]
and [Knowledge Graph][knowledge-graph].
To get the most out of Application Observability, configure OBI to export the following metric families
in the [features][obi-features]
section:

- `application`
- `application_span_otel`
- `application_service_graph`
- `network_flow_packets`
- `application_runtime`

Set the list in the `metrics.features` section of the OBI configuration file, or with the `OTEL_EBPF_METRICS_FEATURES` environment variable.
For example, `OTEL_EBPF_METRICS_FEATURES=application,application_span_otel,application_service_graph,network_flow_packets,application_runtime`.

Application Observability also uses traces and process metrics.
To get them with OBI, enable traces with [full context propagation][obi-context-propagation], and provide a source for [process metrics][process-metrics].

For [host-hours pricing][host-hours-pricing], Application Observability identifies hosts from the `k8s.node.name` or `host.id` resource attribute.
OBI sets these attributes for most deployment models, so you don't need the Beyla `application_host` metric family, which exports the `traces_host_info` metric.

[application-observability]: https://grafana.com/products/cloud/application-observability/
[host-hours-pricing]: https://grafana.com/docs/grafana-cloud/observe-and-act/monitor-applications/application-observability-kg/pricing/
[knowledge-graph]: https://grafana.com/docs/grafana-cloud/knowledge-graph/
[obi-features]: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/#metrics-export-features
[obi-context-propagation]: https://opentelemetry.io/docs/zero-code/obi/distributed-traces/
[process-metrics]: #process-metrics

## Add capabilities that Beyla includes

Beyla includes some capabilities for the Grafana ecosystem that aren't part of OBI.
The following sections describe how to get these capabilities with OBI and other OpenTelemetry projects.

### Process metrics

Beyla provides the following metrics, which follow the
[OpenTelemetry semantic conventions for OS process metrics][process-semconv]:

```text
process.cpu.time
process.cpu.utilization
process.memory.usage
process.memory.virtual
process.disk.io
process.network.io
```

If you use OBI and need these metrics, run an OpenTelemetry Collector on each node, and configure the
[Host Metrics Receiver][hostmetrics]
to report process metrics.

The [process scraper][process-scraper] of the Host Metrics Receiver doesn't report `process.network.io`, so this setup doesn't provide that metric.
The scraper reports `process.cpu.utilization` only when you enable it.

The Host Metrics Receiver sends metrics for all the processes in the system by default.
Beyla sends process metrics only for the services and applications that it instruments.
To report metrics only for the processes that OBI instruments, [configure the Collector to filter out processes][filterprocessor]
that don't match your [OBI service discovery configuration][obi-service-discovery].

[process-semconv]: https://opentelemetry.io/docs/specs/semconv/system/process-metrics/
[hostmetrics]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/hostmetricsreceiver/README.md
[process-scraper]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/hostmetricsreceiver/internal/scraper/processscraper/documentation.md
[filterprocessor]: https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/filterprocessor
[obi-service-discovery]: https://opentelemetry.io/docs/zero-code/obi/configure/service-discovery/

### Survey mode

Beyla has a [survey mode][survey-mode] that discovers your services and detects their programming languages, without instrumenting them.
Grafana Cloud [Instrumentation Hub][instrumentation-hub] uses survey mode to help you configure instrumentation for your services.

OBI doesn't include survey mode.
To follow the work to add survey mode to OBI, refer to the [OBI survey mode issue][obi-survey-issue].

[survey-mode]: ../../configure/service-discovery/#survey-mode
[instrumentation-hub]: https://grafana.com/docs/grafana-cloud/send-data/inst-hub-setup/
[obi-survey-issue]: https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2285

### Integration with Alloy or Collector

Beyla can run as a standalone process, or as a component inside
[Grafana Alloy][alloy-beyla],
the Grafana Labs distribution of the OpenTelemetry Collector.
When Beyla runs inside Alloy, you can manage it with
[Fleet Management][fleet-management],
which lets you manage many collector deployments remotely.

To get similar functionality with OBI, follow these steps:

1. [Build a custom Collector with OBI as a receiver][collector-receiver].
1. Make sure the Collector integrates [OpAMP][opamp].
   For integration instructions, refer to [Get started with Fleet Management and OpenTelemetry Collector][fleet-management-otelcol].

[alloy-beyla]: https://grafana.com/docs/alloy/latest/reference/components/beyla/
[fleet-management]: https://grafana.com/docs/grafana-cloud/send-data/fleet-management/
[collector-receiver]: https://opentelemetry.io/docs/zero-code/obi/configure/collector-receiver/
[opamp]: https://opentelemetry.io/docs/collector/management/
[fleet-management-otelcol]: https://grafana.com/docs/grafana-cloud/send-data/fleet-management/get-started/opentelemetry-collector/

## Next steps

- [Compare Beyla and OpenTelemetry eBPF Instrumentation][compare-obi]
- [OpenTelemetry eBPF Instrumentation documentation][obi-docs]
- [Set up Beyla][setup] to use these capabilities without extra OpenTelemetry components

[obi-docs]: https://opentelemetry.io/docs/zero-code/obi/
[setup]: ../../setup/
