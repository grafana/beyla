---
title: Grafana Beyla
menuTitle: Beyla
description: Learn how to use Grafana Beyla, an eBPF based application auto-instrumentation tool.
weight: 1
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

## Effortless application auto-instrumentation for Application Observability

Instrumenting an application to get metrics and traces typically requires adding a language agent to your application deployment/packages. In some compiled languages like Go or Rust, you have to manually add tracepoints into your code. In both cases, you need to redeploy the instrumented version of your application to your staging/production servers.

Grafana Beyla is an eBPF based application auto-instrumentation tool that lets you easily get started with Application Observability. We leverage eBPF to automatically inspect your application executables and the OS networking layer, to capture basic trace spans about your web transactions, as well as Rate-Errors-Duration (RED) metrics for your Linux HTTP/S and gRPC services. 
All of the data capture is done without any modifications to your application code or configuration.

## Couple of reasons why to use Beyla

- Beyla is vendor agnostic. You can export the generated metrics and traces in OpenTelemetry format, as
well as native Prometheus metrics.
- Beyla can auto-instrument applications written in various programming languages, for example: 
Go, C/C++, Rust, Python, Ruby, Java (including GraalVM Native), NodeJS, .NET and others.
- Beyla is efficient. The instrumentation and the data capture is done with natively compiled code,
even if you are instrumenting applications written in interpreted languages like Python. Because of this,
Beyla provides a way to capture application metrics and traces, with much lesser overhead than using a
language specific instrumentation SDK.
- Beyla is Kubernetes ready. You can run Beyla in any Linux environment, but if you run in Kubernetes, Beyla 
can listen to your Kubernetes API to decorate metrics and traces with Pods and Services metadata. 
- Beyla integrates with the Grafana Agent, so if you are already a Grafana customer, you can easily
get started.

## Get started

Follow the [setup]({{< relref "./setup/_index.md" >}}) documentation to get started with Beyla either as a standalone service or with Docker.

Follow the [Quick start tutorial]({{< relref "./tutorial/index.md" >}}) to get a complete guide to instrument an application with Beyla and data to Grafana Cloud.

## Learn more about Application Observability with Grafana Beyla

{{< section >}}
