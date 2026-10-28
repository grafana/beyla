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
For compiled languages, such as Go and Rust, you often add tracing calls to the code by hand.
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
A faulty kernel module can cause the Linux kernel to hang, but a faulty eBPF program can't.
To learn more about eBPF, refer to [How Beyla works][how].

## eBPF instrumentation improves security

Language SDKs and instrumentation agents become dependencies of your application.
Any vulnerability in an instrumentation library becomes a vulnerability in your application.

Beyla doesn't add a dependency to your application.
Beyla runs as a separate process, and its eBPF programs run in the kernel, outside your application process memory.
A vulnerability in the eBPF instrumentation affects only telemetry collection and generation.

For Java and Node.js applications, Beyla also loads a small language agent into the application process by default.
These agents provide features that eBPF alone can't, such as context propagation.
You can turn the agents off.
For details, refer to [Configure Beyla language specific agents][language-agents].

Beyla runs separately from your application, so you can apply strict access policies to it.
For example, you can configure Beyla to push telemetry and not open any ports.
An SDK or agent inside your application has the same permissions and network access as your application.

Beyla is also safer than proxy-based instrumentation.
A proxy runs outside your application, but it handles all of your application traffic and exposes ports.
If the proxy has a security vulnerability, an attacker can gain access to all of your application traffic.

## eBPF instrumentation needs no application changes

Beyla attaches to your applications while they run.
You can add, remove, or upgrade Beyla without changes to your application code, packages, or deployment.

When you upgrade Beyla, the upgrade applies to all of your instrumented services at once.
You don't need to rebuild or redeploy each service.

## eBPF instrumentation measures latency closer to what clients see

Library and agent instrumentation usually measure service time.
Service time is the time a request handler takes to process a request.
Before a handler starts, a request can wait in an internal framework queue, for example when all threads in the application thread pool are busy.
This instrumentation starts timing when the handler starts, so it misses the wait time.

As a result, library or agent telemetry can report low request durations while clients experience high latency.
This usually happens when a service receives more requests than it can handle, which is when you're most likely to breach a service level objective (SLO) on response time and need to scale.

Beyla observes requests at the kernel network level.
The latency that Beyla reports includes queue time, so it's closer to what the client sees.
When an application can't keep up with incoming requests, queue time can be much larger than service time.
To learn more, refer to [Measuring total request times, instead of service times][requesttime].

## Next steps

- [How Beyla works][how]
- [Choose between Beyla and OpenTelemetry SDKs][compare]
- [Beyla requirements and limitations][requirements]

[distributed-traces]: ../../traces/
[language-agents]: ../../configure/language-agents/
[network]: ../../network/
[requesttime]: ../../traces/requesttime/
[how]: ../how-beyla-works/
[compare]: ../beyla-and-opentelemetry-sdks/
[requirements]: ../requirements/
