---
title: Beyla requirements and limitations
menuTitle: Requirements
description: Check the Linux kernel, Go version, and Linux capability requirements for Grafana Beyla, and learn what eBPF-based auto-instrumentation can and can't capture.
weight: 500
keywords:
  - Beyla
  - eBPF
  - requirements
  - kernel
---

# Beyla requirements and limitations

Before you set up Beyla, check that your hosts meet the following requirements, and review what Beyla can and can't capture.

## Linux kernel

Beyla runs on Linux and requires eBPF support in the host kernel.

Beyla requires Linux kernel 5.8 or later, with BPF Type Format ([BTF][btf]) enabled.
Most Linux distributions enable BTF by default with kernel 5.14 or later.
To check whether your kernel has BTF enabled, verify that `/sys/kernel/btf/vmlinux` exists.
If you need to recompile your kernel to enable BTF, set the `CONFIG_DEBUG_INFO_BTF=y` configuration option.

Beyla also supports Red Hat-based distributions that ship kernel 4.18 with backported eBPF features, such as RHEL 8, CentOS 8, Rocky Linux 8, and AlmaLinux 8.

HTTP header-based trace context propagation requires kernel 5.17 or later.
Beyla uses the `bpf_loop` helper to parse incoming HTTP headers, and earlier kernels don't provide it.
For details, refer to [Distributed traces with Beyla][distributed-traces].

## Go applications

Beyla instruments Go applications built with Go 1.17 or later.
Beyla treats Go applications built with an earlier Go version as non-Go programs, and doesn't use its Go-specific instrumentation for them.

Beyla supports Go applications built with a Go release that's no more than three versions behind the current stable Go release.

## Permissions

Beyla needs elevated privileges to load eBPF programs and inspect processes.
You can run Beyla as root, or grant it only the Linux capabilities it needs for the features you enable.

For application observability, Beyla requires the following capabilities:

- `CAP_BPF`
- `CAP_CHECKPOINT_RESTORE`
- `CAP_DAC_READ_SEARCH`
- `CAP_NET_RAW`
- `CAP_PERFMON`
- `CAP_SYS_PTRACE`

Some features and kernels need more capabilities:

- Trace context propagation, and network observability with Linux Traffic Control, require `CAP_NET_ADMIN`.
- Kernels earlier than 5.11 also require `CAP_SYS_RESOURCE`.
- Kernels earlier than 5.8, such as the RHEL 8 kernel 4.18, require `CAP_SYS_ADMIN` instead of the individual capabilities.

`CAP_SYS_ADMIN` grants all the capabilities that Beyla needs.

For the full list of capabilities, the capabilities each feature needs, and examples of how to run Beyla without root access, refer to [Beyla security, permissions, and capabilities][security].

## Limitations

Beyla creates metrics and spans for the requests that your services receive and send, such as HTTP, gRPC, and database calls.
It doesn't create spans for internal functions in your code.
To instrument specific parts of your code, such as critical operations, use OpenTelemetry SDKs or manual instrumentation.

Beyla trace support varies by language and framework.
For example, Beyla may not correlate spans correctly for reactive Java frameworks.
To compare Beyla and SDK support for your languages and frameworks, refer to [Compare Beyla and OpenTelemetry SDKs][compare].

## Next steps

- [Set up Beyla][setup]
- [Beyla security, permissions, and capabilities][security]
- [Language quickstart guides][quickstart]

[btf]: https://www.kernel.org/doc/html/latest/bpf/btf.html
[distributed-traces]: ../../traces/
[security]: ../../setup/security/
[compare]: ../beyla-and-opentelemetry-sdks/
[setup]: ../../setup/
[quickstart]: ../../quickstart/
