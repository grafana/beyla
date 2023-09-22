---
title: Grafana Beyla
menuTitle: Beyla
description: Learn how to use Grafana Beyla, an eBPF based application auto-instrumentation tool.
weight: 3
cascade:
  labels:
    products:
      - cloud
keywords:
  - Beyla
  - eBPF
  - instrumentation
---

# Grafana Beyla

{{% admonition type="caution" %}}
Beyla is currently in [public preview](/docs/release-life-cycle/). Grafana Labs offers limited support, and breaking changes might occur prior to the feature being made generally available.
{{% /admonition %}}

![Grafana Beyla Logo](https://grafana.com/media/docs/grafana-cloud/beyla/beyla-logo.png)

## eBPF application auto-instrumentation

Instrumenting an application to obtain metrics and traces typically requires adding a language agent to the application deployment/packages. In some compiled languages like Go or Rust, tracepoints have to be manually added to the code. In both cases, the instrumented version of the application must be redeployed to the staging/production servers.

Grafana Beyla is an eBPF-based application auto-instrumentation tool to easily get started with Application Observability. eBPF is used to automatically inspect application executables and the OS networking layer and capture basic trace spans related to web transactions and Rate-Errors-Duration (RED) metrics for Linux HTTP/S and gRPC services. All data capture occurs without any modifications to application code or configuration.

Beyla offers the following features:

- auto-instrument applications written in various programming languages, for example: Go, C/C++, Rust, Python, Ruby, Java (including GraalVM Native), NodeJS, .NET, and others
- efficient instrumentation and the low-overhead data capture with natively compiled code even for interpreted languages
- vendor agnostic data exports in the OpenTelemetry format and as native Prometheus metrics
- runs in any Linux environment
- listen to the Kubernetes API to decorate metrics and traces with Pods and Services metadata
- simple setup for Grafana customers already using Grafana Agent

## Get started

Follow the [setup]({{< relref "./setup/_index.md" >}}) documentation to get started with Beyla either as a standalone
service, with Docker or with Kubernetes.

Follow the [Quick start tutorial]({{< relref "./tutorial/index.md" >}}) to get a complete guide to instrument an application with Beyla and data to Grafana Cloud.

## Learn more about Grafana Beyla

{{< section >}}
