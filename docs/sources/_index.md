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

### Couple of reasons why to use Beyla

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


## Request time instead of service time, for your server-side application code

Grafana Beyla is an eBPF based application auto-instrumentation tool that is able to track the total request time.

When performing a remote service request, the perceived client response time is different from the measured response time at the server.

### Life cycle of a web service request

The following image illustrates an example life cycle of a web service request. From the start of the service request until the end of the service response, the client-perceived response time is near to 140 ms.

![Life cycle of a web service request](https://grafana.com/media/docs/grafana-cloud/beyla/req-life-cycle_2.png)

At the server side, most instrumentation agents are only able to insert probes to measure the service handler time, which is the part of the code that is written by the service owner, while the rest of server-side execution time is at the kernel side or at the language runtime (for example, most languages enqueue incoming HTTP requests for later dispatch).

Under low-load conditions, most of the execution time is spent in the service handler, but in high-load scenarios, many requests might spend a non-negligible time in an internal queue, waiting to be dispatched. In the above timeline, instrumenting only the server handler would report metrics measuring that a web request has required 50ms to execute, while in reality it has spent 120ms at the server side. The service owner would get inaccurate metrics about their services' behavior.

### Track total request time

eBPF allows us to overcome the limitations of manual instrumentation tools. Beyla inserts tracepoints at the kernel connect/receive/write/close functions (also at the Go runtime in the case of Go applications). This low level instrumentation provides more accurate metrics and traces, much closer to the user-perceived response time.

Beyla reports traces that are divided in different spans:

![](https://grafana.com/media/docs/grafana-cloud/beyla/server-side-trace.png)

The above image shows the typical structure of a trace as reported by Beyla:

- an overall span measuring the total time spent by the request at the server side
- a child span measuring the time spent by the request in the queue, waiting to be dispatched
- a child span, starting where the previous child span ends, measuring the time being spent by the actual request handler (application logic)

## Get started

Follow the [setup]({{< relref "./setup/_index.md" >}}) documentation to get started with Beyla either as a standalone service or with Docker.

Follow the [Quick start tutorial]({{< relref "./tutorial/index.md" >}}) to get a complete guide to instrument an application with Beyla and data to Grafana Cloud.

## Learn more about Application Observability

{{< section >}}
