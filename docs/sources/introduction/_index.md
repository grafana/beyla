---
title: Introduction to Grafana Beyla
menuTitle: Introduction
description: Learn what Grafana Beyla is, how it uses eBPF to instrument applications without code changes, and when to use it with OpenTelemetry SDKs.
weight: 200
keywords:
  - Beyla
  - eBPF
  - introduction
---

# Introduction to Grafana Beyla

Grafana Beyla is an eBPF-based application auto-instrumentation tool.
It helps you get started with application observability without changes to your application code or configuration.

Beyla uses eBPF to observe the requests that your services receive and send.
It captures rate, errors, and duration (RED) metrics and trace spans for those requests.
Beyla exports this data in the OpenTelemetry format and as native Prometheus metrics.
You can send the data to Grafana Cloud, Grafana Alloy, an OpenTelemetry Collector, or another compatible backend.

Beyla is the Grafana Labs distribution of [OpenTelemetry eBPF Instrumentation][obi-upstream] (OBI).
Grafana Labs donated the Beyla code to the OpenTelemetry project in 2025.
Beyla builds on OBI and adds features for the Grafana ecosystem.
To learn about the differences, refer to [Compare Beyla and OpenTelemetry eBPF Instrumentation][obi].

## Get started

To start using Beyla, complete the following steps:

- Check the [requirements and limitations][requirements] to confirm Beyla runs in your environment
- [Set up Beyla][setup] with Docker, Kubernetes, or Grafana Alloy
- Follow a [language quickstart][quickstart] to instrument your first service
- [Configure Beyla][configure] to choose which services to instrument and where to send data

## Learn more

Learn more about Beyla with the following topics:

- [Why use Grafana Beyla][why]: Understand the benefits of eBPF-based instrumentation
- [How Grafana Beyla works][how]: Learn how Beyla uses eBPF to capture metrics and traces
- [Compare Beyla and OpenTelemetry SDKs][compare]: Decide when to use Beyla, SDKs, or both
- [Compare Beyla and OpenTelemetry eBPF Instrumentation][obi]: Understand how Beyla relates to the upstream OBI project
- [Beyla requirements and limitations][requirements]: Check the kernel, Go version, and permission requirements
- [Beyla security, permissions, and capabilities][security]: Run Beyla with the minimum Linux capabilities

[obi-upstream]: https://opentelemetry.io/docs/zero-code/obi/
[obi]: ./obi/
[setup]: ../setup/
[quickstart]: ../quickstart/
[configure]: ../configure/
[security]: ../setup/security/
[why]: ./why-beyla/
[how]: ./how-beyla-works/
[compare]: ./beyla-and-opentelemetry-sdks/
[requirements]: ./requirements/
