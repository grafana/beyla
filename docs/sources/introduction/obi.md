---
title: Using OpenTelemetry eBPF Instrumentation instead of Beyla
menuTitle: OpenTelemetry eBPF Instrumentation instead of Beyla

description: How to use upstream OpenTelemetry eBPF instrumentation as a replacement for Beyla

weight: 500
keywords:
  - Beyla
  - eBPF
  - OpenTelemetry eBPF Instrumentation
aliases:
  - ../obi/ # /docs/beyla/<BEYLA_VERSION>/obi/
---

# Using OpenTelemetry eBPF Instrumentation instead of Beyla

Grafana Beyla is the Grafana Labs distribution of
[OpenTelemetry eBPF Instrumentation][obi-docs] (OBI).

Grafana Labs [donated the Beyla code to the OpenTelemetry project][donation-blog] in 2025 as OBI.
A community of contributors, including Grafana Labs, maintains OBI.

This page helps you use the upstream OBI distribution instead of Beyla.
OBI works with the Grafana Cloud OTLP endpoint, and with any OpenTelemetry or Prometheus collector.
Some Beyla features aren't available in OBI.
OBI works in the Grafana ecosystem without them, but you might need other OpenTelemetry projects to replace them.

[obi-docs]: https://opentelemetry.io/docs/zero-code/obi/
[donation-blog]: https://grafana.com/blog/opentelemetry-ebpf-instrumentation-beyla-donation/

## Differences between OBI and Beyla

The eBPF auto-instrumentation code lives in the [OBI code repository][obi-repo],
and the [Grafana Beyla code repository][beyla-repo] imports it as a library.
Every feature that's available in OBI is also available in Beyla.

Beyla also has features that OBI doesn't.
Both projects are open source and vendor-neutral, and Beyla adds features that make it easier to adopt eBPF-based auto-instrumentation in the Grafana ecosystem.

The two projects also have different release cycles.
Beyla usually releases more often than OBI, so some features are available in Beyla before they're in an OBI release.

For metrics and attributes that don't follow an OpenTelemetry semantic convention
because none exists yet, Beyla prefixes the names with `beyla_` while
OBI prefixes them with `obi_`.
For example, Beyla reports the network-level flow bytes metric as `beyla_network_flow_bytes_total`, and OBI reports it as `obi_network_flow_bytes_total`.

[obi-repo]: https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation
[beyla-repo]: https://github.com/grafana/beyla

### Configuration

Beyla and OBI use the same YAML configuration schema.
Most configuration examples in this documentation also work with OBI, except for the Beyla features in the next section.

The OpenTelemetry documentation also describes
[how to configure OBI from a YAML configuration file][obi-configure].

The environment variable prefixes differ.
OBI uses the `OTEL_EBPF_` prefix, and Beyla uses the `BEYLA_` prefix.
Beyla also accepts the `OTEL_EBPF_` prefix.
The rest of each environment variable name is the same in both projects.

For example, to set the logging verbosity level, OBI accepts the `OTEL_EBPF_LOG_LEVEL` environment
variable, and Beyla accepts both `BEYLA_LOG_LEVEL` and `OTEL_EBPF_LOG_LEVEL`.

OBI and Beyla both support the [OpenTelemetry common environment variables][otel-env-vars],
for example `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_EXPORTER_OTLP_PROTOCOL`.

[obi-configure]: https://opentelemetry.io/docs/zero-code/obi/configure/
[otel-env-vars]: https://opentelemetry.io/docs/languages/sdk-configuration/otlp-exporter/

## Beyla features that are missing in OBI

Beyla provides the following features that OBI doesn't:

- Process metrics
- Survey mode
- Integration inside Grafana Alloy
- Grafana AI Observability support
- Connecting spans for Tempo service graph metrics

The following subsections describe upstream alternatives for some of these features.

### Process metrics

Beyla provides the following metrics, which follow the
[OpenTelemetry semantic conventions for OS process metrics][process-semconv]:
```
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

The Host Metrics Receiver sends metrics for all the processes in the system by default.
Beyla sends process metrics only for the services and applications that it instruments.
To report metrics only for the processes that OBI instruments, [configure the Collector to filter out processes][filterprocessor]
that don't match your [OBI service discovery configuration][obi-service-discovery].

[process-semconv]: https://opentelemetry.io/docs/specs/semconv/system/process-metrics/
[hostmetrics]: https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/hostmetricsreceiver/README.md
[filterprocessor]: https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/filterprocessor
[obi-service-discovery]: https://opentelemetry.io/docs/zero-code/obi/configure/service-discovery/

### Survey mode

Beyla has a [survey mode][survey-mode] that discovers your services and detects their programming languages, without instrumenting them.
Grafana Cloud [Instrumentation Hub][instrumentation-hub] uses survey mode to help you configure instrumentation for your services.

OBI doesn't have a replacement for survey mode.
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

### Grafana AI Observability support

OBI can generate spans and traces from your generative AI clients.
To use these traces with [Grafana Cloud AI Observability][ai-observability],
configure your instrumentation pipeline:

- Export OBI traces to an OpenTelemetry Collector that forwards them to Grafana Cloud.
- In the OpenTelemetry Collector:
  - Add a `sigil.generation.id` attribute to each span.
    Set the value to `gen_` followed by a random UUID, for example `gen_01234567-90ab-cdef-0123-456789abcdef`.
  - If a span doesn't have a `gen_ai.conversation.id` attribute, use a transform processor to set it to the value of the `gen_ai.response.id` attribute.
  - Optional: To reduce costs, drop spans that don't belong to a generative AI workload.
    For example, drop any span that doesn't contain a `gen_ai.*` attribute.

[ai-observability]: https://grafana.com/docs/grafana-cloud/monitor-applications/ai-observability/

## Use OBI with Grafana Cloud Application Observability and Knowledge Graph

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

For full functionality, also enable traces with
[full context propagation][obi-context-propagation],
and provide a source for [process metrics][process-metrics].

[application-observability]: https://grafana.com/products/cloud/application-observability/
[knowledge-graph]: https://grafana.com/docs/grafana-cloud/knowledge-graph/
[obi-features]: https://opentelemetry.io/docs/zero-code/obi/configure/export-data/#metrics-export-features
[obi-context-propagation]: https://opentelemetry.io/docs/zero-code/obi/distributed-traces/
[process-metrics]: #process-metrics

