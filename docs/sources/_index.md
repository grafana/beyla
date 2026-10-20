---
review_date: 2026-10-20
title: Grafana Beyla
menuTitle: Beyla
description: Learn how to use Grafana Beyla, an eBPF-based application auto-instrumentation tool.
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
---

# Grafana Beyla

![Grafana Beyla logo](https://grafana.com/media/docs/grafana-cloud/beyla/beyla-logo.png)

Grafana Beyla is an eBPF-based application auto-instrumentation tool that helps you get started with Grafana Cloud Application Observability.
Beyla uses eBPF to automatically inspect application executables and the operating system networking layer.
You don't need to change your application code or configuration.

Other instrumentation methods usually require you to add a language agent to your application deployment or packages.
In compiled languages such as Go or Rust, you usually add instrumentation code by hand.

Beyla captures trace spans for web transactions and Rate, Errors, Duration (RED) metrics for Linux HTTP, HTTPS, and gRPC services.
It also captures calls to databases, caches, and message brokers, such as SQL databases, Redis, and Kafka.

Beyla does the following:

- Instruments applications written in Go, C/C++, Rust, Python, Ruby, Java, Node.js, .NET, and other languages, including GraalVM native images
- Captures data with natively compiled eBPF code, even for interpreted languages
- Exports vendor-agnostic data in the OpenTelemetry format and as native Prometheus metrics
- Generates [distributed traces][distributed-traces]
- Runs on Linux hosts that meet the [requirements][requirements]
- Decorates metrics and traces with Pod and Service metadata from the Kubernetes API when it runs in Kubernetes
- Integrates with Grafana Alloy
- Builds on [OpenTelemetry eBPF Instrumentation (OBI)][obi]

## eBPF overview and how it differs from other types of instrumentation

eBPF lets you attach programs to different points of the Linux kernel.
eBPF programs run in privileged mode and can inspect kernel runtime information such as system calls and the network stack.
They can also attach to probes in user-space applications.

User-space applications, such as Beyla, load the eBPF code into the kernel.
The kernel and user-space applications share information through mechanisms that the eBPF specification defines, such as ring buffers, arrays, and hash maps.

![Beyla eBPF architecture](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/ebpf-arch.svg)

### eBPF instrumentation is safe and improves security

eBPF programs compile to their own [Virtual Machine instruction set][instruction-set].
Before a program runs, the kernel verifier checks it for memory access safety and finite execution time.
Unlike earlier technologies, such as natively compiled kernel modules, a poorly programmed eBPF probe can't cause the Linux kernel to hang.

The kernel can then compile eBPF programs with a Just-In-Time (JIT) compiler for the native host architecture, such as x86-64 or ARM64, for fast execution.

Unlike language-specific SDK libraries or instrumentation agents, eBPF instrumentation doesn't add anything to your application as a dependency.
The eBPF instrumentation code, which extracts and generates the application telemetry, doesn't run within your application process memory.

When you add an instrumentation library dependency to your code, any vulnerabilities in the library become vulnerabilities in your application.
With eBPF, your application doesn't carry Beyla code as a dependency, so a vulnerability in Beyla doesn't ship with your application.

For Java and Node.js, Beyla also injects a small language agent into the application process for TLS capture, context propagation, and runtime metrics.
To turn off these agents, refer to [Language specific agents][language-agents].

eBPF instrumentation runs outside your application process, so you can control the network access of Beyla separately from your application.
For example, you can ensure that Beyla doesn't open any ports and only pushes the generated telemetry.
With language-specific SDK libraries or instrumentation agents, telemetry export shares the network access of your application.

Beyla eBPF instrumentation also avoids the security risks of proxy-based black-box instrumentation.
Proxies don't run within your application process, but they're separate programs that expose ports and handle all of your application traffic.
If the proxy has a security vulnerability, an attacker can gain access to that traffic.

### eBPF instrumentation is non-intrusive

Beyla attaches to running processes, so you can instrument your applications without restarting them.
The eBPF instrumentation runs outside of the application process, so the eBPF probes don't add library code to your application.

Beyla runs as a separate process, so you can stop, restart, or upgrade Beyla without restarting your applications.
When you upgrade Beyla, the upgrade takes effect on all of your instrumented services when Beyla restarts.

### eBPF instrumentation measures total request time

Most library or agent-based instrumentation measures only the service time, which is the time a request handler takes to process a request.
However, requests might wait in an internal framework queue before a handler processes them.

For example, requests wait for a handler when all threads in the application thread pool are busy.
Library-level instrumentation usually doesn't account for these wait times.

Library or agent instrumentation can therefore report low request durations even though clients experience high latency.
This is especially problematic if you have service level objectives, or SLOs, on response times.
This situation typically arises when too many requests overload a service, which is also when you're most likely to breach SLOs.

Beyla measures requests at the kernel level, and for Go applications also at the Go runtime level.
Therefore, Beyla latency numbers include queue times and are closer to the response time that the client sees.
When an application can't keep up with incoming requests, queue times can be orders of magnitude longer than service times.

For more information, refer to [Measuring total request times, instead of service times][requesttime].

## Choose between Beyla and OpenTelemetry SDKs

Use the following matrix to decide whether to use Beyla, OpenTelemetry SDKs, or both.

- _Recommended_: best default choice
- _Supported with limitations_: works, but there are important limitations
- _Not recommended_: use another approach

{{< fixed-table >}}

| Technology | Beyla: RED metrics | Beyla: traces | OpenTelemetry SDKs: traces | Notes |
| --- | --- | --- | --- | --- |
| **Baseline (any service)** | Recommended | Supported with limitations | Recommended | Beyla is strongest as a zero-code baseline layer for RED metrics and service graphs. SDKs remain the default recommendation for detailed distributed tracing. |
| **Service already using OpenTelemetry SDK** | Recommended | Not recommended | Recommended | When Beyla detects that a service exports OpenTelemetry traces or metrics, it stops generating its own traces or RED metrics for that service. If the SDK exports only traces, Beyla still generates RED metrics. Refer to [Exclude services instrumented with OpenTelemetry][exclude-otel-instrumented-services] to change this. If Beyla also generates span metrics or service graphs, set `span.metrics.skip=true` in the `OTEL_RESOURCE_ATTRIBUTES` environment variable of the SDK-instrumented service. This setting prevents the OpenTelemetry Collector or Grafana Tempo from generating duplicate metrics from SDK traces. Beyla adds this flag automatically on its own traces when it generates span metrics and exports metrics through OTLP or Prometheus. |
| **Go HTTP / HTTP2 / HTTPS** | Recommended | Recommended | Supported with limitations | Go is a first-class case for eBPF tracing. Beyla provides zero-code instrumentation for Go HTTP, HTTP2, and gRPC. You can also add the Go OpenTelemetry SDK for deeper application-level detail. |
| **Go gRPC** | Recommended | Recommended | Supported with limitations | Go gRPC is one of the strongest Beyla tracing cases. |
| **Java HTTP (standard servlet / thread-pool)** | Recommended | Supported with limitations | Recommended | Beyla tracing can work for Java in standard thread-pool models, but SDK traces are still the more robust default. |
| **Java reactive / thread-switching** | Recommended | Not recommended | Recommended | Reactive Java isn't a good fit for eBPF trace correlation. Beyla might emit stand-alone spans that don't belong to the correct trace. |
| **Node.js HTTP** | Recommended | Supported with limitations | Recommended | Beyla tracing works reasonably well for Node.js, but SDKs still provide richer spans and stronger log and runtime correlation. |
| **Python HTTP** | Recommended | Supported with limitations | Recommended | Python tracing support is reasonable, but asynchronous context propagation has framework-specific limitations. |
| **Python asynchronous** | Recommended | Supported with limitations | Recommended | Beyla supports Python `asyncio`. Use Beyla for zero-code coverage; add the Python OpenTelemetry SDK for richer spans and stronger runtime correlation. |
| **Ruby** | Recommended | Supported with limitations | Recommended | Ruby support is reasonable, but asynchronous and framework coverage is narrower than with SDK tracing. |
| **.NET** | Recommended | Supported with limitations | Recommended | Beyla tracing works well when the .NET service isn't the first in the call chain. If it's the entry point, tracing might not work correctly. Validate behavior before relying on Beyla traces for .NET in production. |
| **Mixed polyglot environment** | Recommended | Supported with limitations | Recommended where available | A practical pattern is Beyla everywhere for baseline metrics and service graphs, then SDKs on the services where you need runtime metrics, log correlation, deep tracing, or custom telemetry. |

[exclude-otel-instrumented-services]: ./configure/service-discovery/#exclude-otel-instrumented-services

{{< /fixed-table >}}

### Practical guidance

Use Beyla first when you need:

- Zero-code rollout
- RED metrics and service graphs
- Broad baseline visibility across many services
- Coverage for services where SDK rollout is hard or impossible

Use OpenTelemetry SDKs or agents when you need:

- The most reliable distributed tracing
- Internal spans and framework and library detail
- Trace-to-log correlation where Beyla can't inject trace context into logs, for example without `CAP_SYS_ADMIN` or on kernels in lockdown mode
- Runtime metrics beyond the opt-in [application runtime metrics][application-runtime-metrics] that Beyla provides
- Custom span attributes, events, and business telemetry

Use Beyla and SDKs together when:

- You want Beyla to provide baseline metrics and service graphs
- You want SDKs to provide deep traces

### Considerations

- For non-Go services, especially asynchronous or reactive frameworks, validate Beyla trace support before you deploy to production.
  The same applies to OpenTelemetry SDKs.
  SDK coverage varies by language and framework, and if no SDK instrumentation exists for your framework, the SDK collects no data.
- By default, Beyla turns off its own tracing for services that export OpenTelemetry traces.
  If you change this default, verify the behavior before you run Beyla tracing and SDK tracing together for the same service.

## Requirements

- Linux with kernel 5.8 or later with [BPF Type Format (BTF)][btf] enabled.
  Most Linux distributions enable BTF by default from kernel 5.14.
  To check whether your kernel has BTF enabled, verify that `/sys/kernel/btf/vmlinux` exists on your system.
  Beyla also accepts a `vmlinux` file in the standard `libbpf` fallback locations, for example _`/boot/vmlinux-<KERNEL_RELEASE>`_.
  If you need to recompile your kernel to enable BTF, set the configuration option `CONFIG_DEBUG_INFO_BTF=y`.
- Beyla also runs on kernel 4.18 in Red Hat-based distributions, such as RHEL8, CentOS 8, Rocky8, and AlmaLinux8, which backport eBPF-related patches.
- eBPF enabled on the host.
- Root privileges or the [Linux capabilities][linux-capabilities] that Beyla needs.
- Beyla uses Go-specific instrumentation for programs built with Go 1.17 or later.
  It treats programs built with earlier Go versions as non-Go programs.
  Beyla supports Go applications built with a major **Go version no earlier than 3 versions** behind the current stable major release.
- HTTP header-based trace context propagation requires Linux kernel 5.17 or later.
  Beyla uses the `bpf_loop` helper to parse incoming HTTP headers, and that helper isn't available in earlier kernels.
  If your kernel backports `bpf_loop`, set `ebpf.override_bpfloop_enabled: true` or `BEYLA_OVERRIDE_BPF_LOOP_ENABLED=true` to skip the kernel version check.

### Linux capabilities

Instead of root privileges, you can run Beyla with the following capabilities: `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, `CAP_PERFMON`, `CAP_BPF`, `CAP_CHECKPOINT_RESTORE`, and `CAP_NET_RAW`.
On kernels earlier than 5.11, Beyla also needs `CAP_SYS_RESOURCE`.
On RHEL-based 4.18 kernels, Beyla needs `CAP_SYS_ADMIN` instead of these capabilities.

Some Beyla features require further permissions.
For example, network observability with Linux Traffic Control and trace context propagation both require `CAP_NET_ADMIN`.
You have to enable both features explicitly.

Trace-to-log correlation also requires `CAP_SYS_ADMIN` and a kernel that isn't in lockdown mode.
On kernels 5.10 and later, Go library-level context propagation has the same requirements.

For the full list of capabilities that Beyla requires, refer to [Beyla security, permissions, and capabilities][security].

## Limitations

Beyla only provides generic metrics and transaction-level trace span information.
Use language agents or manual instrumentation when you need to choose what to instrument in your code, for example, to focus on critical operations.

## Get started

- Follow the [Set up Beyla][setup] documentation to run Beyla with Docker or Kubernetes.
- Follow the [Beyla quickstart guides][quickstart] to instrument an application written in a specific language.

## Learn more about Grafana Beyla

The following topics explain how to configure, run, and use Beyla:

{{< section >}}

[distributed-traces]: ./distributed-traces/
[requirements]: #requirements
[obi]: ./obi/
[instruction-set]: https://docs.kernel.org/bpf/standardization/instruction-set.html
[language-agents]: ./configure/language-agents/
[requesttime]: ./requesttime/
[btf]: https://www.kernel.org/doc/html/latest/bpf/btf.html
[linux-capabilities]: #linux-capabilities
[application-runtime-metrics]: ./configure/export-data/#application-runtime-metrics
[security]: ./security/
[setup]: ./setup/
[quickstart]: ./quickstart/
