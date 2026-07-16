---
title: Using OpenTelemetry eBPF Instrumentation instead of Beyla
menuTitle: OpenTelemetry eBPF Instrumentation instead of Beyla

description: How to use upstream OpenTelemetry eBPF instrumentation as a replacement for Beyla

weight: 24
keywords:
  - Beyla
  - eBPF
  - OpenTelemetry eBPF Instrumentation
---

# Using OpenTelemetry eBPF Instrumentation instead of Beyla

Grafana Beyla is the distribution of the
[OpenTelemetry eBPF Instrumentation](https://opentelemetry.io/docs/zero-code/obi/)
(a.k.a. OBI) software that is currently supported by Grafana.

The Grafana Beyla code was donated in 2025 to the OpenTelemetry project as
OBI, which is now maintained by a consortium of contributors
that includes (but is not limited to) Grafana.

This document is aimed at helping users who want to use the upstream OBI distribution
instead of Grafana Beyla. OBI works out of the box with the Grafana OTLP
endpoint (or any intermediate OpenTelemetry/Prometheus collector), but there are
some Beyla features that are not available in OBI. They are not indispensable
for the correct functioning of OBI within the Grafana ecosystem, but users
might want open source alternatives for some of them.

## Differences between OBI and Grafana

Since its donation to OpenTelemetry, the code that implements all the eBPF-based
auto-instrumentation has been moved to the [OBI code repository](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation)
and is imported as a library by the [Grafana Beyla code repository](https://github.com/grafana/beyla).
This means that **every feature that is available in OBI is also available in Beyla**.

However, not every feature in Beyla is currently available in OBI. While
both are 100% open source, vendor-neutral solutions based on open standards and
specifications, Beyla provides some extra features that smooth the adoption
of eBPF-based auto-instrumentation within the Grafana ecosystem.

Also, the stable release cycles of the two projects are different. In this case, and unlike
other open source projects, the Beyla release cycle is faster than OBI's, so
some features might be available in Beyla before they are in OBI.

For metrics and attributes that don't follow an OpenTelemetry semantic convention
because none exists yet, Beyla prefixes the names with `beyla_` while
OBI prefixes them with `obi_`. For example, the network-level flow bytes metric is reported as
`beyla_network_flow_bytes_total` in Beyla and `obi_network_flow_bytes_total` in OBI.

### Configuration

Both Beyla and OBI follow the same YAML configuration schema, so any configuration example
you might find in this documentation is generally compatible with OBI, with the exception
of the Beyla features that are missing in OBI, which are listed in the following section.

As an alternative to the Beyla documentation, the OpenTelemetry site already documents
[how to configure OBI from a YAML configuration file](https://opentelemetry.io/docs/zero-code/obi/configure/).

A notable difference concerns configuring OBI with environment variables. OBI prefixes
its configuration environment variables with `OTEL_EBPF_*` while Beyla prefixes them with `BEYLA_*`
(Beyla also accepts the `OTEL_EBPF_*` prefix). The rest of the environment variable names
remain the same in both cases.

For example, to set the logging verbosity level, OBI accepts the `OTEL_EBPF_LOG_LEVEL` environment
variable, and Beyla accepts both `BEYLA_LOG_LEVEL` and `OTEL_EBPF_LOG_LEVEL`.

The [OpenTelemetry common environment variables](https://opentelemetry.io/docs/languages/sdk-configuration/otlp-exporter/)
(for example `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_PROTOCOL`) remain supported
by both OBI and Beyla in the same way.

## Beyla features that are missing in OBI

This section lists some features that are provided by Beyla but not by OBI:

* Process metrics
* Survey mode
* Integration inside Grafana Alloy

The following subsections provide upstream-only alternatives for these features.

### Process metrics

Beyla provides the following metrics, which follow the
[OpenTelemetry semantic conventions for OS process metrics](https://opentelemetry.io/docs/specs/semconv/system/process-metrics/):
```
process.cpu.time
process.cpu.utilization
process.memory.usage
process.memory.virtual
process.disk.io
process.network.io
```

If you are using OBI but still require the above metrics, you need to install an instance
of the OpenTelemetry Collector on each node and configure the
[Host Metrics Receiver](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/hostmetricsreceiver/README.md)
to report process metrics.

Unlike the Collector's Host Metrics Receiver, which sends metrics from all the processes in the system
by default, Beyla only sends process metrics belonging to the services and applications that are instrumented.
If you want to restrict the process metrics to only the processes reporting application-level metrics,
you should manually [configure the OpenTelemetry Collector to filter out processes](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/processor/filterprocessor)
that do not match the [OBI Service Discovery configuration](https://opentelemetry.io/docs/zero-code/obi/configure/service-discovery/).

### Survey mode

Beyla has a special [survey mode](./configure/service-discovery.md#survey-mode) that is
aimed exclusively at discovering which of your currently uninstrumented services can be instrumented by Beyla.
It enables faster auto-configuration of your services within
[Grafana Cloud's Instrumentation Hub](https://grafana.com/docs/grafana-cloud/get-started/inst-hub-setup/).

At the moment, there is no direct replacement for Beyla's survey mode in OBI, but there is
an ongoing initiative to port [Beyla's survey mode to OBI](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2285).
We will update this document as the survey mode porting progresses.

### Integration with Alloy or Collector

While Beyla can run as a standalone process, it can also run as an embedded component inside
[Grafana Alloy](https://grafana.com/docs/alloy/latest/reference/components/beyla/),
an OpenTelemetry collector from Grafana. When it runs as an Alloy component, it can make
use of some exclusive features, such as the integration with
[Fleet Management](https://grafana.com/docs/grafana-cloud/send-data/fleet-management/),
which allows you to remotely manage multiple telemetry collector deployments at scale.

To achieve similar functionality with OBI, you need to follow these steps:
1. [Build a custom Collector with OBI as a receiver](https://opentelemetry.io/docs/zero-code/obi/configure/collector-receiver/).
2. Make sure the resulting collector integrates [OpAMP](https://opentelemetry.io/docs/collector/management/),
and check the [Get started with Fleet Management and OpenTelemetry Collector](https://grafana.com/docs/grafana-cloud/send-data/fleet-management/get-started/opentelemetry-collector/)
documentation for integration instructions.

## Using OBI with asserts
## Using OBI with App O11y



