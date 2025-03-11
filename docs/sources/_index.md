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
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/
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
- distributed traces for Go services
- runs in any Linux environment
- listen to the Kubernetes API to decorate metrics and traces with Pods and Services metadata
- simple setup for Grafana customers already using Grafana Alloy

## Requirements

- Linux with Kernel 5.8 or higher with BPF Type Format [(BTF)](https://www.kernel.org/doc/html/latest/bpf/btf.html)
  enabled. BTF became enabled by default on most Linux distributions with kernel 5.14 or higher.
  You can check if your kernel has BTF enabled by verifying if `/sys/kernel/btf/vmlinux` exists on your system.
  If you need to recompile your kernel to enable BTF, the configuration option `CONFIG_DEBUG_INFO_BTF=y` must be
  set.
- eBPF enabled in the host.
- For instrumenting Go programs, they must have been compiled with at least Go 1.17. We currently
  support Go applications built with a major **Go version no earlier than 3 versions** behind the current
  stable major release.
- Administrative access rights to execute Beyla.

## Get started

- Follow the [language quickstart guides](quickstart/) for quick instructions
  about how to set up Beyla to instrument applications written in a particular language.

- Follow the [setup](setup/) documentation to get started with Beyla either as a standalone
  service, with Docker or with Kubernetes.

- Follow the [tutorials](tutorial/) to get a complete guide to instrument an application with Beyla and data to Grafana Cloud.

## Learn more about Grafana Beyla

{{< section >}}
