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
---

# Grafana Beyla

![Grafana Beyla Logo](https://grafana.com/media/docs/grafana-cloud/beyla/beyla-logo.png)

## eBPF application auto-instrumentation

Instrumenting an application to obtain metrics and traces typically requires adding a language agent to the application deployment/packages.
In some compiled languages like Go or Rust, you must manually add tracepoints to the code.

Grafana Beyla is an eBPF-based application auto-instrumentation tool to easily get started with Application Observability.
Beyla uses eBPF to automatically inspect application executables and the OS networking layer, and capture trace spans related to web transactions and Rate Errors Duration (RED) metrics for Linux HTTP/S and gRPC services.
All data capture occurs without any modifications to application code or configuration.

Beyla offers the following features:

- auto-instrument applications written in various programming languages, for example: Go, C/C++, Rust, Python, Ruby, Java (including GraalVM Native), NodeJS, .NET, and others
- efficient instrumentation and the low-overhead data capture with natively compiled code even for interpreted languages
- vendor agnostic data exports in the OpenTelemetry format and as native Prometheus metrics
- [distributed traces](./distributed-traces/) with Beyla 2
- runs in any Linux environment
- listens to the Kubernetes API to decorate metrics and traces with Pods and Services metadata
- Grafana Alloy integration

## eBPF overview and how it differs from other types of instrumentation

eBPF allows you to attach applications to different points of the Linux Kernel. eBPF applications run in privileged mode and allow you to specify the runtime information of the Linux Kernel: system calls, network stack, as well as inserting probes in user space applications.

The eBPF code is loaded from ordinary applications running in user space. The kernel and the user space applications can share information through a set of well defined communication mechanisms, which are provided by the eBPF specification. For example: ring buffers, arrays, hash maps, etc.

![Beyla eBPF architecture](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/ebpf-arch.svg)

### eBPF instrumentation is safe and improves security

The eBPF programs are safe and compiled for their own [Virtual Machine instruction set](https://docs.kernel.org/bpf/standardization/instruction-set.html) and run in a sandboxed environment that verifies each loaded eBPF program for memory access safety and finite execution time. Unlike previous technologies, such as natively compiled kernel modules, there is no chance that a poorly programmed probe can cause the Linux Kernel to hang.

eBPF binaries get verified and compiled with a Just-In-Time (JIT) compiler for the native host architecture such as x86-64 or ARM64 for efficient and fast execution.

Unlike other types of instrumentation, for example language specific SDK libraries or instrumentation agents, eBPF instrumentation doesn't add anything to your application as a dependency. This means that the eBPF instrumentation code, which extracts and generates all of the application telemetry, doesn't run within your application process memory. When you add an instrumentation library dependency to your code, any vulnerabilities in the instrumentation library are all of a sudden vulnerabilities in your application as well. This is inherently true for all application dependencies, and instrumentation dependencies are not any different. With eBPF, since all instrumentation is done outside of your application process memory, any vulnerability to the eBPF user-space components impacts just the telemetry collection and generation part of your system.

Since eBPF instrumentation runs out of your application process, you can apply very restrictive access policies to the eBPF agent and secure the telemetry generation process. For example, you can ensure that the eBPF agent (Beyla) doesn't open any ports and only uses push for the generated telemetry, which wouldn't be feasible if the application is instrumented using language specific SDK libraries or instrumentation agents.

Beyla eBPF instrumentation is also safer than proxy based black box instrumentation. When you use a proxy service to generate telemetry for a service that's not instrumented, the problem of security concerns still applies. While proxies don't run within your process application space, they are separate programs that handle all of your application traffic and expose ports. If there's a security vulnerability in the proxy, an attacker can gain access to your application traffic, by virtue that the proxy handles all of your application traffic.

### eBPF instrumentation is non-intrusive

Beyla can instrument all of your applications without restart and without disrupting your application performance. The eBPF instrumentation can be added and removed without any impact to the system or application performance. Since the eBPF instrumentation runs outside of the application process, it doesn't add any memory, CPU, IO or locking overhead to your application performance. Any instability of the eBPF monitoring stack is purely an instability of that component. This means that performance or functional bugs in the eBPF instrumentation, do not cause performance or stability issues to your applications. 

Since eBPF instrumentation can be added or removed without disrupting the application behavior, this also means that you can safely update/upgrade your observability. Upgrading Beyla to a newer version, for example to gain access to new functionality or to upgrade the OpenTelemetry standard, is painless and it immediately takes an effect on all of your instrumented services.

### eBPF instrumentation produces correct latency metrics

All library or agent based instrumentation has the same fundamental flaw when it comes down to measuring request latency. They instrument the service time, that is, the time it takes for a request handler to process a request. However, requests may need to wait in an internal framework queue before they are being serviced. A common example of when requests are waiting for a handler, is when all threads in the incoming application thread pool are busy. These wait times are never accounted for by library level instrumentation.

As a result, the telemetry provided by library or agent instrumentation, may indicate low request duration times even though clients experience high latency. This is especially problematic if there are SLOs on response times. In fact, this situation typically arises when the service is overloaded, which is a very common scenario in which SLOs can be breached and application workloads need to be scaled.

Beyla looks at interactions from outside of the application, on the kernel's network level. Therefore, the latency numbers produced by Beyla represent the behavior as seen by the client, including queue times. This is not just a nuance: Queue times may be orders of magnitude higher than the actual service times if an application is struggling to keep up with the amount of requests being sent its way. To read more about this, refer to the [Measuring total request times, instead of service times](./requesttime.md) section of the documentation.

## Determine compatibility

Before you get started, you can use the following matrix to determine whether you should use Beyla, OpenTelemetry SDKs, or both.

- _Recommended_: best default choice
- _Supported with limitations_: works, but there are important limitations
- _Not recommended_: use another approach

{{< fixed-table >}}

| Technology | Beyla: RED metrics | Beyla: traces | OTel SDKs: traces | Notes |
| --- | --- | --- | --- | --- |
| **Baseline (any service)** | Recommended | Supported with limitations | Recommended | Beyla is strongest as a zero-code baseline layer for RED metrics and service graphs. SDKs remain the default recommendation for detailed distributed tracing. |
| **Service already using OTel SDK** | Recommended | Not recommended | Recommended | Beyla automatically disables its own tracing when a service is already instrumented with OTel. If Beyla is also generating span metrics or service graphs, set `span.metrics.skip=true` via `OTEL_RESOURCE_ATTRIBUTES` to prevent the Collector or Tempo from duplicating metrics based on SDK traces. Beyla adds this flag automatically on its own traces when span metrics or service graph generation is enabled. |
| **Go HTTP / HTTP2 / HTTPS** | Recommended | Recommended | Supported with limitations | Go is a first-class case for eBPF tracing. Beyla provides zero-code instrumentation for Go HTTP, HTTP2, and gRPC. Users can additionally add the Go OTel SDK for deeper app-level detail. |
| **Go gRPC** | Recommended | Recommended | Supported with limitations | Go gRPC is one of the strongest Beyla tracing cases. |
| **Java HTTP (standard servlet / thread-pool)** | Recommended | Supported with limitations | Recommended | Beyla tracing can work for Java in standard thread-pool models, but SDK traces are still the more robust default. |
| **Java reactive / thread-switching** | Recommended | Not recommended | Recommended | Reactive Java is not a good fit for eBPF trace correlation. Beyla may emit stand-alone spans that are not attached to the correct trace. |
| **Node.js HTTP** | Recommended | Supported with limitations | Recommended | Beyla tracing works reasonably well for Node.js, but SDKs still provide richer spans and stronger log/runtime correlation. |
| **Python HTTP** | Recommended | Supported with limitations | Recommended | Python tracing support is reasonable, but asynchronous context propagation has framework-specific limitations. |
| **Python asynchronous** | Recommended | Supported with limitations | Recommended | Beyla supports Python `asyncio`. Use Beyla for zero-code coverage; add the Python OTel SDK for richer spans and stronger runtime correlation. |
| **Ruby** | Recommended | Supported with limitations | Recommended | Ruby support is reasonable, but async/framework coverage is narrower than with SDK tracing. |
| **.NET** | Recommended | Supported with limitations | Recommended | Beyla tracing works well when the .NET service is not the first in the call chain. If it is the entry point, tracing may not work correctly. Validate behavior before relying on Beyla traces for .NET in production. |
| **Mixed polyglot environment** | Recommended | Supported with limitations | Recommended where available | A practical pattern is Beyla everywhere for baseline metrics and service graphs, then SDKs on the services where you need deep tracing, log correlation, runtime metrics, or custom telemetry. |

{{< /fixed-table >}}

### Practical guidance

Use Beyla first when you need:

- zero-code rollout
- RED metrics and service graphs
- broad baseline visibility across many services
- coverage for services where SDK rollout is hard or impossible

Use OTel SDKs or agents when you need:

- the most reliable distributed tracing
- internal spans and framework/library detail
- trace-to-log correlation (note: Beyla also supports trace-to-log correlation, including for SDK-instrumented services where the SDK does not provide it)
- runtime metrics
- custom span attributes, events, and business telemetry

Use Beyla and SDKs together when:

- you want Beyla to provide baseline metrics and service graphs
- you want SDKs to provide deep traces

### Important considerations

- For non-Go services, especially asynchronous or reactive frameworks, validate Beyla trace support before deploying to production. The same applies to OTel SDKs; SDK coverage varies significantly by language and framework, and if there is no SDK instrumentation for your framework of choice, no data is collected.
- Do not run Beyla tracing and SDK tracing in parallel for the same service unless you have verified the behavior.

## Requirements

- Linux with Kernel 5.8 or higher with BPF Type Format [(BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html)
  enabled. BTF became enabled by default on most Linux distributions with kernel 5.14 or higher.
  You can check if your kernel has BTF enabled by verifying if `/sys/kernel/btf/vmlinux` exists on your system.
  If you need to recompile your kernel to enable BTF, the configuration option `CONFIG_DEBUG_INFO_BTF=y` must be
  set.
- Beyla also supports RedHat-based distributions: RHEL8, CentOS 8, Rocky8, AlmaLinux8, and others, which ship a Kernel 4.18 that backports eBPF-related patches.
- eBPF enabled in the host.
- For instrumenting Go programs, compile with at least Go 1.17. Beyla support Go applications built with a major **Go version no earlier than 3 versions** behind the current stable major release.
- Administrative access rights to execute Beyla.

## Limitations

Beyla only provides generic metrics and transaction level trace span information. Language agents and manual instrumentation are still recommended so that you can specify the granularity of each part of the code to be instrumented, putting the focus on your critical operations.

While most eBPF programs require elevated privileges, Beyla allows you to specify finer grained permissions to run with minimum required permissions, such as: `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, `CAP_PERFMON`, `CAP_BPF`, `CAP_CHECKPOINT_RESTORE`, and `CAP_NET_RAW`.

Some Beyla functionality requires further permissions, for example using the network observability probes with Linux Traffic Control requires `CAP_NET_ADMIN`, but it's a feature you have to optionally enable.

For a comprehensive list of capabilities required by Beyla, refer to [Security, permissions and capabilities](security/).

## Get started

- Follow the [setup](setup/) documentation to get started with Beyla either with Docker or Kubernetes.

- Follow the [language quickstart guides](quickstart/) for quick instructions
  about how to set up Beyla to instrument applications written in a particular language.

## Learn more about Grafana Beyla

{{< section >}}
