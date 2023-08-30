---
title: Grafana Beyla
menuTitle: Beyla
description: Learn about Grafana Beyla an eBPF based application auto-instrumentation tool.
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

Grafana Beyla is an eBPF based application auto-instrumentation tool to track total request time.

When performing a remote service request, the perceived client response time is different from the measured response time at the server.

## Life cycle of a web service request

The following image illustrate an example life cycle of a web service request. from the start of the service request until the end of the service response, the client-perceived response time is near to 140 ms.

![Life cycle of a web service request](https://grafana.com/media/docs/grafana-cloud/beyla/req-life-cycle_2.png)

At the server side, most instrumentation agents are only able to insert probes to measure the service handler time, which is the part of the code that is written by the service owner, while the rest of server-side execution time is at the kernel side or at the language runtime (for example, most languages enqueue incoming HTTP requests for later dispatch).

Under low-load conditions, most of the execution time is spent in the service handler, but in high-load scenarios, many requests might spend a non-negligible time in an internal queue, waiting to be dispatched. In the above timeline, instrumenting only the server handler would report metrics measuring that a web request has required 50ms to execute, while in reality it has spent 120ms at the server side. The service owner would get inaccurate metrics about their services behavior.

## Track total request time

eBPF allows us to overcome the limitations of manual instrumentation tools. Beyla inserts tracepoints at the kernel connect/receive/write/close functions (also at the Go runtime in the case of Go applications). This low level instrumentation provides more accurate metrics and traces, much closer to the user-perceived response time.

Beyla reports traces that are divided in different spans:

![](https://grafana.com/media/docs/grafana-cloud/beyla/server-side-trace.png)

The above image shows the typical structure of a trace as reported by Beyla:

- an overall span measuring the total time spent by the request at the server side
- a child span measuring the time spent by the request in the queue, waiting to be dispatched
- a child span, starting where the previous child span ends, measuring the time being spent by the actual request handler (application logic)

## Get started

Follow the the [setup]({{< relref "./setup/_index.md" >}}) documentation to get started with Beyla either as a standalone service or with Docker.

Follow the [Quick start tutorial]({{< relref "./tutorial/index.md" >}}) to get a complete guide to instrument an application with Beyla and data to Grafana Cloud.

## Learn more about Application Observability

{{< section >}}
