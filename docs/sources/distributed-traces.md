---
title: Distributed traces with Beyla
menuTitle: Distributed traces
description: Learn about Beyla's distributed traces support.
weight: 22
keywords:
  - Beyla
  - eBPF
  - distributed traces
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/distributed-traces/
---

# Distributed traces with Beyla

## Introduction

Beyla supports distributed traces for Go applications, both HTTP/S and gRPC, with some limitations and version restrictions.

Go distributed tracing is implemented through the propagation of the [W3C `traceparent`](https://www.w3.org/TR/trace-context/) header value. `traceparent` context propagation is automatic and it doesn't require any action or configuration.

Beyla will read any incoming trace context header values, track the Go program execution flow and propagate the trace context by automatically adding the `traceparent` field in outgoing HTTP/gRPC requests. If an application already adds the `taceparent` field in outgoing requests, Beyla will use that value for tracing instead its own generated trace context. If Beyla cannot find an incoming `traceparent` context value, it will generate one according to the W3C specification.

## Limitations

### Kernel integrity mode limitations

In order to write the `traceparent` value in outgoing HTTP/gRPC request headers, Beyla needs to write to the process memory using the [bpf_probe_write_user](https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html) eBPF helper. Since kernel 5.14 (with fixes backported to the 5.10 series) this helper is protected (and unavailable to BPF programs) if the Linux Kernel is running in `integrity` lockdown mode. Kernel integrity mode is typically enabled by default if the Kernel has [Secure Boot](https://wiki.debian.org/SecureBoot) enabled, but it can also be enabled manually.

Beyla will automatically check if it can use the `bpf_probe_write_user` helper, and enable context propagation only if it's allowed by the kernel configuration. Verify the Linux Kernel lockdown mode by running the following command:

```shell
cat /sys/kernel/security/lockdown
```

If that file exists and the mode is anything other than `[none]`, Beyla will not be able to perform context propagation and distributed tracing will be disabled.

### Configuring distributed tracing for containerized environments (including Kubernetes)

Because of the Kernel lockdown mode restrictions, Docker and Kubernetes configuration files should mount the `/sys/kernel/security/` volume for the **Beyla docker container** from the host system. This way Beyla can correctly determine the Linux Kernel lockdown mode. Here's an example Docker compose configuration, which ensures Beyla has sufficient information to determine the lockdown mode:

```yaml
version: '3.8'

services:
  ...
  beyla:
    image: grafana/beyla:latest
    environment:
      BEYLA_CONFIG_PATH: "/configs/beyla-config.yml"
    volumes:
      - /sys/kernel/security:/sys/kernel/security
```

If the volume is not mounted, Beyla will assume that the Linux Kernel is not running in integrity mode.
