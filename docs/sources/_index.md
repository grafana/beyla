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
- listen to the Kubernetes API to decorate metrics and traces with Pods and Services metadata
- simple setup for Grafana customers already using Grafana Alloy

## eBPF overview

eBPF allows you to attach applications to different points of the Linux Kernel. eBPF applications run in privileged mode and allow you to specify the runtime information of the Linux Kernel: system calls, network stack, as well as inserting probes in user space applications.

The eBPF applications are safe and compiled for their own [Virtual Machine instruction set](https://docs.kernel.org/bpf/standardization/instruction-set.html) and run in a sandboxed environment that verifies each loaded eBPF program for memory access safety and finite execution time. Unlike previous technologies, such as natively compiled kernel modules, there is no chance that a poorly programmed probe can cause the Linux Kernel to hang.

eBPF binaries get verified and compiled with a Just-In-Time (JIT) compiler for the native host architecture such as x86-64 or ARM64 for efficient and fast execution.

The eBPF code is loaded from ordinary applications running in user space. The kernel and the user space applications can share information through a set of well defined communication mechanisms, which are provided by the eBPF specification. For example: ring buffers, arrays, hash maps, etc.

![Beyla eBPF architecture](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/ebpf-arch.svg)

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

Beyla has its limitations too. It only provides generic metrics and transaction level trace span information. Language agents and manual instrumentation is still recommended, so that you can specify the granularity of each part of the code to be instrumented, putting the focus on your critical operations.

While most eBPF programs require elevated privileges, Beyla allow you to specify finer grained permissions to run with minimum required permissions, such as: `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, `CAP_PERFMON`, `CAP_BPF`, `CAP_CHECKPOINT_RESTORE`, and `CAP_NET_RAW`.

Some Beyla functionality requires further permissions, for example using the network observability probes with Linux Traffic Control requires `CAP_NET_ADMIN`, but it's a feature you have to optionally enable.

For a comprehensive list of capabilities required by Beyla, refer to [Security, permissions and capabilities](security/).

## Get started

- Follow the [setup](setup/) documentation to get started with Beyla either with Docker or Kubernetes.

- Follow the [language quickstart guides](quickstart/) for quick instructions
  about how to set up Beyla to instrument applications written in a particular language.

## Learn more about Grafana Beyla

{{< section >}}
