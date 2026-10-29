---
title: Grafana Beyla
menuTitle: Beyla
description: Learn how to use Grafana Beyla, an eBPF based application auto-instrumentation tool.
weight: 3
cascade:
  labels:
    products:
      - oss
keywords:
  - Beyla
  - eBPF
  - instrumentation
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/
  - /docs/beyla/latest/tutorial/getting-started/
  - /docs/grafana-cloud/monitor-applications/beyla/stability/
  - /docs/beyla/latest/stability/
hero:
  title: Grafana Beyla
  level: 1
  image: /media/docs/grafana-cloud/beyla/beyla-logo.png
  width: 110
  height: 110
  description: >-
    Grafana Beyla uses eBPF to instrument your applications automatically.
    Get RED metrics and traces for your services with no changes to application code or configuration, and export them in OpenTelemetry and Prometheus formats.
cards:
  title_class: pt-0 lh-1
  items:
    - title: Introduction to Beyla
      href: ./introduction/
      description: Learn what Beyla is, how it works, and when to use it with OpenTelemetry SDKs.
    - title: Set up Beyla
      href: ./setup/
      description: Run Beyla as a standalone process, as a Docker container, or in Kubernetes.
    - title: Quickstart guides
      href: ./quickstart/
      description: Instrument a C/C++, Go, Java, Node.js, Python, Ruby, or Rust service.
    - title: Configure Beyla
      href: ./configure/
      description: Choose which services to instrument, where to send data, and which attributes to add.
    - title: Exported metrics
      href: ./metrics/
      description: Review the metrics that Beyla exports in OpenTelemetry and Prometheus formats.
    - title: Distributed traces
      href: ./distributed-traces/
      description: Learn how Beyla propagates trace context between your services.
    - title: Network metrics
      href: ./network/
      description: Measure network traffic between nodes, containers, Pods, and Services.
    - title: Security
      href: ./security/
      description: Learn which Linux capabilities Beyla needs and how to run it without root access.
---

{{< docs/hero-simple key="hero" >}}

---

## Overview

Instrumenting every service with a language SDK or agent takes time, and some services are hard or impossible to instrument that way.
Beyla gives you a baseline of application observability across your services, in many languages, from one tool.
You can then add OpenTelemetry SDKs where you need deeper detail.

### Instrument applications without code changes

Beyla attaches eBPF probes to the Linux kernel and to your running services.
It captures metrics and trace spans for HTTP/S and gRPC services, and for database and messaging clients such as SQL, Redis, and Kafka.

### One tool for every language

Beyla instruments services written in Go, Java, .NET, Node.js, Python, Ruby, Rust, C/C++, and more.
Beyla observes requests at the kernel level, so it can also instrument services that don't have an OpenTelemetry or Prometheus SDK.
Run Beyla on Linux hosts, in containers, in Kubernetes, or as part of Grafana Alloy.

### Built on open standards

Send Beyla data to Grafana Cloud, Grafana Alloy, an OpenTelemetry Collector, Prometheus, or another compatible backend.
In Kubernetes, Beyla adds metadata such as Pod and namespace names to your metrics and traces, so you can find which workload has a problem.

### Part of OpenTelemetry

Grafana Labs donated Beyla to the OpenTelemetry project in 2025 as [OpenTelemetry eBPF Instrumentation][obi] (OBI).
Beyla is the Grafana Labs distribution of OBI, with extra features for the Grafana ecosystem.

[obi]: ./introduction/obi/

## Explore

Find the topics you need to set up, configure, and use Beyla:

{{< card-grid key="cards" type="simple" >}}
