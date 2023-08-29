---
title: Grafana Beyla
menuTitle: Beyla
description: Learn about Grafana Beyla, the eBPF based application auto-instrumentation tool.
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

## eBPF based application auto-instrumentation tool

## Track total request time

When performing a remote service request, the response time that is
perceived by the client is different from the response time that is measured
at the server-side. Often, these values might be really distant.

![](https://grafana.com/media/docs/grafana-cloud/beyla/req-life-cycle.png)

The above image shows an example; from the start of the service request until the end
of the service response, the client-perceived response time is near to 140 ms.

At the server side, most instrumentation agents are only able to insert probes to measure
the service handler time, which is the part of the code that is written by the service
owner, while the rest of server-side execution time is at the kernel side or at the
language runtime (for example, most languages enqueue incoming HTTP requests for later
dispatch).

Under low-load conditions, most of the execution time will be spent in the service handler,
but in high-load scenarios, many requests might spend a non-negligible time
in an internal queue, waiting to be dispatched. In the above timeline, instrumenting only the
server handler would report metrics measuring that a web request has required 50ms to execute,
while in reality it has spent 120ms at the server side. The service owner would get really
inaccurate metrics about their services behavior.

eBPF allows us to overcome the limitations of manual instrumentation tools. The eBPF auto-instrumentation
tool inserts tracepoints at the kernel connect/receive/write/close functions (also at the
Go runtime in the case of Go applications). This low level instrumentation provides more accurate metrics and
traces, much closer to the user-perceived response time.

Concretely, the eBPF auto-instrumentation tool reports traces that are divided in different spans:

![](https://grafana.com/media/docs/grafana-cloud/beyla/server-side-trace.png)

The above image shows the typical structure of a trace as reported by the eBPF auto-instrumentation tool:

* An overall span measuring the total time spent by the request at the server side.
* A child span measuring the time spent by the request in the queue, waiting to be dispatched.
* A child span, starting where the previous child span ends, measuring the time being spent
  by the actual request handler (the code with business logic, as provided by the application
  developer).

## Get started

Follow the the [setup]({{< relref "./setup/_index.md" >}}) documentation to get started with Beyla.

[Getting started tutorial]({{< relref "./tutorial/index.md" >}})

## Learn more about Application Observability

{{< section >}}
