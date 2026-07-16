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

### Configuration

(TODO: develop)

* Same YAML structure
* Same environment variables, but different prefix `OTEL_EBPF_*` instead of `BEYLA_`.
  * Anyway, Beyla still supports `OTEL_EBPF_*` prefix (but not the reverse).

### Beyla features that are missing in OBI

(TODO: develop)

* Process metrics
* Survey mode
* K8s OTEL SDK auto-injection
* Integration inside Grafana Alloy
  * Fleet Management
  * Instrumentation Hub

## Process metrics

TODO: explain how to setup Host Metrics Receiver

## Survey mode

There is no direct replacement. TODO: link to service discovery documentation.

## K8s OTEL auto-injection

TODO: Point to the OpenTelemetry operator and SDK injector projects. Explain
the limitations (for example, you need to be explicit in which services
are instrumented by OBI and which services are instrumented by the Operator)

## Integration with Alloy or Collector

- Can't run embedded in the same executable (WIP: https://github.com/open-telemetry/opentelemetry-collector/issues/15430)
- How to integrate with a collector/alloy
- No integration with Instrumentation Hub by now
- No integration with Fleet management by now



