---
title: Why use Grafana Beyla
menuTitle: Why Beyla
description: Learn why eBPF-based auto-instrumentation with Grafana Beyla is safe, doesn't change your applications, and measures request latency the way your clients experience it.
weight: 100
keywords:
  - Beyla
  - eBPF
  - instrumentation
---

# Why use Grafana Beyla

To get metrics and traces from an application, you usually add a language agent or SDK to the application deployment or packages.
For some compiled languages, such as Go and Rust, you must also add tracepoints to the code by hand.
You repeat this work for every service and every language you run.

Beyla takes a different approach.
It uses eBPF to observe your applications from outside the application process.
You get application observability without changes to application code or configuration.

## What Beyla provides

Beyla offers the following features:

- Automatic instrumentation for applications written in Go, C/C++, Rust, Python, Ruby, Java, Node.js, .NET, and more.
  Java support includes GraalVM Native applications.
- RED metrics and trace spans for HTTP/S and gRPC services, and for database and messaging clients such as SQL, Redis, Kafka, and MongoDB
- Low-overhead data capture with natively compiled code, even for interpreted languages
- Vendor-neutral data export in the OpenTelemetry format and as native Prometheus metrics
- [Distributed traces][distributed-traces] through automatic trace context propagation
- [Network metrics][network] between endpoints such as nodes, containers, Pods, and Services
- Kubernetes metadata, such as Pod and namespace names, on your metrics and traces
- Integration with Grafana Alloy

## eBPF instrumentation is safe

The kernel verifies each eBPF program before it loads it.
The verifier checks that the program accesses memory safely and finishes in a finite time.
Unlike a kernel module, a faulty eBPF probe can't cause the Linux kernel to hang.
To learn more about eBPF, refer to [How Beyla works][how].

## eBPF instrumentation improves security

Language SDKs and instrumentation agents become dependencies of your application.
Any vulnerability in an instrumentation library becomes a vulnerability in your application.

Beyla doesn't add anything to your application as a dependency.
The code that extracts and generates telemetry runs in a separate process, outside your application process memory.
A vulnerability in Beyla affects only telemetry collection and generation.

Beyla runs separately from your application, so you can apply strict access policies to it.
For example, you can configure Beyla to push telemetry and not open any ports.
That isn't possible when your application includes an SDK or agent.

Beyla is also safer than proxy-based instrumentation.
A proxy runs outside your application, but it handles all of your application traffic and exposes ports.
If the proxy has a security vulnerability, an attacker can gain access to all of your application traffic.

## eBPF instrumentation doesn't change your applications

Beyla attaches its probes to your applications from outside.
You can add, remove, or upgrade Beyla without changes to your application code, packages, or deployment.

When you upgrade Beyla, the upgrade applies to all of your instrumented services at once.
You don't need to rebuild or redeploy each service.

## eBPF instrumentation measures latency as clients see it

Library and agent instrumentation measure service time.
Service time is the time a request handler takes to process a request.
Before a handler starts, a request can wait in an internal framework queue, for example when all threads in the application thread pool are busy.
Library instrumentation doesn't count this wait time.

As a result, library or agent telemetry can report low request durations while clients experience high latency.
This usually happens when a service receives more requests than it can handle, which is when you're most likely to breach a service level objective (SLO) on response time and need to scale.

Beyla observes requests at the kernel network level, outside the application.
The latency that Beyla reports matches what the client sees, including queue time.
When an application can't keep up with incoming requests, queue time can be much larger than service time.
To learn more, refer to [Measuring total request times, instead of service times][requesttime].

## Next steps

- [How Beyla works][how]
- [Choose between Beyla and OpenTelemetry SDKs][compare]
- [Beyla requirements and limitations][requirements]

[distributed-traces]: ../../traces/
[network]: ../../network/
[requesttime]: ../../traces/requesttime/
[how]: ../how-beyla-works/
[compare]: ../beyla-and-opentelemetry-sdks/
[requirements]: ../requirements/
