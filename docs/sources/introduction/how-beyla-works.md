---
title: How Grafana Beyla works
menuTitle: How Beyla works
description: Learn how Grafana Beyla uses eBPF probes in the Linux kernel and language runtimes to capture metrics and traces, and how it exports the data.
weight: 200
keywords:
  - Beyla
  - eBPF
  - architecture
---

# How Grafana Beyla works

Beyla uses eBPF to capture metrics and traces from your applications.
This page explains what eBPF is, how Beyla uses it to instrument your services, and where the data goes.

## eBPF overview

eBPF lets you attach programs to different points of the Linux kernel.
eBPF programs run in privileged mode and can inspect runtime information from the kernel, such as system calls and the network stack.
eBPF programs can also insert probes into user space applications.

An ordinary application running in user space loads the eBPF code into the kernel.
The kernel and the user space application share information through communication mechanisms that the eBPF specification provides, such as ring buffers, arrays, and hash maps.

![Beyla eBPF architecture](https://grafana.com/media/docs/grafana-cloud/beyla/tutorial/ebpf-arch.svg)

eBPF programs compile to their own [virtual machine instruction set][instruction-set] and run in a sandbox.
Before the kernel loads a program, it verifies that the program accesses memory safely and finishes in a finite time.
After verification, a just-in-time (JIT) compiler compiles the program for the native host architecture, such as x86-64 or ARM64, so it runs efficiently.

## How Beyla instruments an application

Beyla runs on the same host as the applications it instruments, outside the application processes.
Beyla follows these steps:

1. Beyla finds the processes to instrument, based on your [service discovery][service-discovery] configuration.
1. Beyla inspects the executable of each process to identify the language and runtime it uses.
1. Beyla attaches eBPF probes to the process.
   Kernel probes capture network activity, such as connections, reads, and writes.
   User space probes capture function calls in the language runtime or in libraries, for example in Go applications.
1. When the application receives or sends a request, the probes capture events about the request and pass them to Beyla.
1. Beyla converts the events into metrics and trace spans, and adds metadata, such as Kubernetes Pod and namespace names.
1. Beyla exports the metrics and traces in the OpenTelemetry format, as native Prometheus metrics, or both.

Beyla can also [propagate trace context][distributed-traces] between services, so spans from different services join the same distributed trace.

Beyla captures requests at the kernel level, so it measures the full time a request spends on the server, including time in internal queues.
To learn more, refer to [Measuring total request times, instead of service times][requesttime].

## Where Beyla sends data

Beyla exports data in open formats, so you can choose your backend:

- Send OpenTelemetry metrics and traces to Grafana Alloy or an OpenTelemetry Collector for processing and routing.
- Send OpenTelemetry metrics and traces directly to an OTLP endpoint, such as Grafana Cloud.
- Expose a Prometheus endpoint that Prometheus or Grafana Alloy can scrape.

To configure exports, refer to [Configure Beyla Prometheus and OpenTelemetry data export][export-data].

## Where Beyla runs

You can run Beyla in the following ways:

- As a standalone process on a Linux host or virtual machine
- As a Docker container
- In Kubernetes, as a DaemonSet or as a sidecar container
- Inside Grafana Alloy, with the `beyla.ebpf` component

To choose a deployment method, refer to [Set up Beyla][setup].

## Beyla and OpenTelemetry eBPF Instrumentation

Beyla is the Grafana Labs distribution of OpenTelemetry eBPF Instrumentation (OBI).
The eBPF instrumentation code lives in the OBI project, and Beyla imports it as a library.
Every OBI feature is available in Beyla.
Beyla adds features for the Grafana ecosystem, such as process metrics.
To learn about the differences, refer to [Using OpenTelemetry eBPF Instrumentation instead of Beyla][obi].

## Next steps

- [Choose between Beyla and OpenTelemetry SDKs][compare]
- [Beyla requirements and limitations][requirements]
- [Set up Beyla][setup]

[instruction-set]: https://docs.kernel.org/bpf/standardization/instruction-set.html
[service-discovery]: ../../configure/service-discovery/
[distributed-traces]: ../../traces/
[requesttime]: ../../traces/requesttime/
[export-data]: ../../configure/export-data/
[setup]: ../../setup/
[obi]: ../obi/
[compare]: ../beyla-and-opentelemetry-sdks/
[requirements]: ../requirements/
