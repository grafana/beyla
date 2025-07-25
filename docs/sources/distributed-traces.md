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

Beyla supports distributed traces for applications with some limitations and kernel version restrictions.

The distributed tracing is implemented through the propagation of the [W3C `traceparent`](https://www.w3.org/TR/trace-context/) header value. `traceparent` context propagation is automatic and it doesn't require any action or configuration.

Beyla reads any incoming trace context header values, tracks the program execution flow and propagates the trace context by automatically adding the `traceparent` field in outgoing HTTP/gRPC requests. If an application has already added the `traceparent` field in outgoing requests, Beyla uses that value for tracing instead its own generated trace context. If Beyla cannot find an incoming `traceparent` context value, it generates one according to the W3C specification.

## Implementation

The trace context propagation is implemented in two different ways:

1. By writing the outgoing header information at network level
2. By writing the header information at library level for Go

Depending on the programming language your service is written in, Beyla uses one or both approaches of context propagation.
We use these multiple approaches to implement context propagation, because writing memory with eBPF depends on the kernel
configuration and the Linux system capabilities granted to Beyla. For more details on this topic, see our KubeCon NA 2024
talk [So You Want to Write Memory with eBPF?](https://www.youtube.com/watch?v=TUiVX-44S9s).

The context propagation at **network level** is **disabled** by default and can be enabled by setting the environment variable
`BEYLA_BPF_CONTEXT_PROPAGATION=all` or by modifying the Beyla configuration file:

```yaml
ebpf:
  context_propagation: "all"

```

### Context propagation at network level

The context propagation at network level is implemented by writing the trace context information in the outgoing HTTP headers as well at the TCP/IP packet level.
HTTP context propagation is fully compatible with any other OpenTelemetry based tracing library. This means that Beyla instrumented services correctly
propagate the trace information, when sending to and receiving from services instrumented with the OpenTelemetry SDKs. We use
[Linux Traffic Control (TC)](https://en.wikipedia.org/wiki/Tc_(Linux)) to perform the adjustment of the network packets, which requires that other eBPF
programs that use Linux Traffic Control chain properly with Beyla. For special considerations
regarding Cilium CNI, consult our [Cilium Compatibility](../cilium-compatibility/) guide.

For TLS encrypted traffic (HTTPS), Beyla is unable to inject the trace information in the outgoing HTTP headers and instead it injects the information
at TCP/IP packet level. Because of this limitation, Beyla is only able to send the trace information to other Beyla instrumented services. L7 proxies
and load balancers disrupt the TCP/IP context propagation, because the original packets are discarded and replayed downstream.
Parsing incoming trace context information from OpenTelemetry SDK instrumented services still works.

gRPC and HTTP2 are not supported at the moment.

This type of context propagation works for any programming language and doesn't require that Beyla runs in `privileged` mode or has
`CAP_SYS_ADMIN` granted. For more details, see the [Distributed traces and context propagation](../configure/metrics-traces-attributes/) configuration section.

#### Kubernetes Configuration

The recommended way to deploy Beyla on Kubernetes with distributed tracing support at network level is as `DaemonSet`.

The following `Kubernetes` configuration must be used:
- Beyla must be deployed as a `DaemonSet` with host network access (`hostNetwork: true`).
- The `/sys/fs/cgroup` path from the host must be volume mounted as local `/sys/fs/cgroup` path.
- The `CAP_NET_ADMIN` capability must be granted to the Beyla container.

The following YAML snippet shows an example Beyla deployment configuration:

```yaml
    spec:
      serviceAccount: beyla
      hostPID: true           # <-- Important. Required in DaemonSet mode so Beyla can discover all monitored processes
      hostNetwork: true       # <-- Important. Required in DaemonSet mode so Beyla can see all network packets
      dnsPolicy: ClusterFirstWithHostNet
      containers:
      - name: beyla
        resources:
          limits:
            memory: 120Mi
        terminationMessagePolicy: FallbackToLogsOnError
        image: "beyla:latest"
        imagePullPolicy: "Always"
        command: [ "/beyla", "--config=/config/beyla-config.yml" ]
        env:
          - name: OTEL_EXPORTER_OTLP_ENDPOINT
            value: "http://otelcol:4318"
          - name: BEYLA_KUBE_METADATA_ENABLE
            value: "autodetect"
        securityContext:
          runAsUser: 0
          readOnlyRootFilesystem: true
          capabilities:
            add:
              - BPF                 # <-- Important. Required for most eBPF probes to function correctly.
              - SYS_PTRACE          # <-- Important. Allows Beyla to access the container namespaces and inspect executables.
              - NET_RAW             # <-- Important. Allows Beyla to use socket filters for http requests.
              - CHECKPOINT_RESTORE  # <-- Important. Allows Beyla to open ELF files.
              - DAC_READ_SEARCH     # <-- Important. Allows Beyla to open ELF files.
              - PERFMON             # <-- Important. Allows Beyla to load BPF programs.
              - NET_ADMIN           # <-- Important. Allows Beyla to inject HTTP and TCP context propagation information.
        volumeMounts:
          - name: cgroup
            mountPath: /sys/fs/cgroup # <-- Important. Allows Beyla to monitor all newly sockets to track outgoing requests.
          - mountPath: /config
            name: beyla-config
      tolerations:
      - effect: NoSchedule
        operator: Exists
      - effect: NoExecute
        operator: Exists
      volumes:
      - name: beyla-config
        configMap:
          name: beyla-config
      - name: cgroup
        hostPath:
          path: /sys/fs/cgroup
```

If `/sys/fs/cgroup` is not mounted as a local volume path for the Beyla `DaemonSet` some requests may not
have their context propagated. We use this volume path to listen to newly created sockets.

#### Kernel version limitations

The network level context propagation incoming headers parsing generally requires kernel 5.17 or newer for the addition and use of BPF loops.

Some patched kernels, such as RHEL 9.2, may have this functionality ported back. Setting BEYLA_OVERRIDE_BPF_LOOP_ENABLED skips kernel checks in the case your kernel includes the functionality but is lower than 5.17.

### Go context propagation by instrumenting at library level

This type of context propagation is only supported for Go applications and uses eBPF user memory write support (`bpf_probe_write_user`).
The advantage of this approach is that it works for HTTP/HTTP2/HTTPS and gRPC with some limitations, however the use of `bpf_probe_write_user` requires
the Beyla is granted `CAP_SYS_ADMIN` or it's configured to run as `privileged` container.

#### Kernel integrity mode limitations

In order to write the `traceparent` value in outgoing HTTP/gRPC request headers, Beyla needs to write to the process memory using the [**bpf_probe_write_user**](https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html) eBPF helper. Since kernel 5.14 (with fixes backported to the 5.10 series) this helper is protected (and unavailable to BPF programs) if the Linux Kernel is running in `integrity` **lockdown** mode. Kernel integrity mode is typically enabled by default if the Kernel has [**Secure Boot**](https://wiki.debian.org/SecureBoot) enabled, but it can also be enabled manually.

Beyla automatically checks if it can use the `bpf_probe_write_user` helper, and enables context propagation only if it's allowed by the kernel configuration. Verify the Linux Kernel **lockdown** mode by running the following command:

```shell
cat /sys/kernel/security/lockdown
```

If that file exists and the mode is anything other than `[none]`, Beyla cannot perform context propagation and distributed tracing is disabled.

#### Distributed tracing for Go in containerized environments (including Kubernetes)

Because of the Kernel **lockdown** mode restrictions, Docker and Kubernetes configuration files should mount the `/sys/kernel/security/` volume for the **Beyla docker container** from the host system. This way Beyla can correctly determine the Linux Kernel **lockdown** mode. Here's an example Docker compose configuration, which ensures Beyla has sufficient information to determine the **lockdown** mode:

```yaml
services:
  ...
  beyla:
    image: grafana/beyla:latest
    environment:
      BEYLA_CONFIG_PATH: "/configs/beyla-config.yml"
    volumes:
      - /sys/kernel/security:/sys/kernel/security
      - /sys/fs/cgroup:/sys/fs/cgroup
```

If the `/sys/kernel/security/` volume is not mounted, Beyla assumes that the Linux Kernel is not running in integrity mode.
