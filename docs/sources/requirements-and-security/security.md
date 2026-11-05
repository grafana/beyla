---
title: Beyla security, permissions, and capabilities
menuTitle: Security
description: The Linux capabilities that Grafana Beyla needs for each feature, what each capability does, and how Beyla checks them at startup.
weight: 200
keywords:
  - Beyla
  - eBPF
  - security
  - capabilities
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/security/
  - ../security/ # /docs/beyla/<BEYLA_VERSION>/security/
  - ../setup/security/ # /docs/beyla/<BEYLA_VERSION>/setup/security/
---

# Beyla security, permissions, and capabilities

Grafana Beyla needs access to various Linux interfaces to instrument applications, such as reading from the `/proc` filesystem, loading eBPF programs, and managing network interface filters.
Many of these operations require elevated permissions.
You can run Beyla as root, or grant Beyla only the Linux capabilities that the features you enable need.
Linux capabilities split root privileges into smaller units that you grant to a process or executable.
Refer to the [capabilities manual page][capabilities-man] for details.

## Capabilities by feature

Beyla needs the following capabilities for each feature.
If you enable more than one feature, grant the capabilities of each.

| Feature                                               | Required capabilities                                                                                                            | Configuration                                                 |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Application observability                             | `CAP_BPF`, `CAP_CHECKPOINT_RESTORE`, `CAP_DAC_READ_SEARCH`, `CAP_NET_RAW`, `CAP_PERFMON`, `CAP_SYS_PTRACE`                       | [Configure Beyla service discovery][service-discovery]        |
| Trace context propagation                             | The application observability capabilities and `CAP_NET_ADMIN`. Go library-level context propagation also needs `CAP_SYS_ADMIN`. | [Enable context propagation][context-propagation]             |
| Log injection                                         | The application observability capabilities and `CAP_SYS_ADMIN`                                                                   | `ebpf.log_enricher`                                           |
| Network observability with the `socket_filter` source | `CAP_BPF`, `CAP_NET_RAW`, `CAP_PERFMON`                                                                                          | [Beyla Network Metrics configuration options][network-config] |
| Network observability with the `tc` source            | `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`                                                                                        | [Beyla Network Metrics configuration options][network-config] |
| TCP statistics                                        | `CAP_BPF`, `CAP_NET_RAW`, `CAP_PERFMON`, `CAP_SYS_PTRACE`                                                                        | [Metrics export features][export-features]                    |

On kernels earlier than 5.11, every feature also needs `CAP_SYS_RESOURCE`.

## Capability details

The following list describes how Beyla uses each capability:

`CAP_BPF`
: Required for every feature on kernels 5.8 and later.
  Enables general BPF functionality and socket filter programs, used for capturing network flows in *network observability*.

`CAP_NET_RAW`
: Used to create `AF_PACKET` raw sockets, which Beyla uses to attach socket filter programs.
  Required for *network observability* with the `socket_filter` source, for *application observability*, and for TCP statistics.

`CAP_NET_ADMIN`
: Required to load `BPF_PROG_TYPE_SCHED_CLS` TC programs, which Beyla uses when `network.source` is `tc`.
  Beyla also requires it when you enable any trace context propagation mode.

`CAP_PERFMON`
: Used for trace context propagation, general *application observability* and network flow monitoring.
  Allows direct packet access by TC programs, loading eBPF probes in the kernel and pointer arithmetic used by these programs.

`CAP_DAC_READ_SEARCH`
: Bypasses file read, and directory read and execute, permission checks.
  Beyla checks for it at startup when you enable *application observability*.

`CAP_CHECKPOINT_RESTORE`
: Reads the `/proc/<pid>/map_files` symbolic links of other processes, which Beyla uses to open the libraries a process has loaded.

`CAP_SYS_PTRACE`
: Access to `/proc/pid/exe` and executable modules, used by Beyla to scan executable symbols and instrument different parts of a program.

`CAP_SYS_RESOURCE`
: Increase the amount of locked memory available, **kernels < 5.11** only.

`CAP_SYS_ADMIN`
: Required for Go library-level trace context propagation on kernels 5.10 and later, which doesn't work when the kernel runs in [integrity mode][lockdown], and for log injection, which you configure under `ebpf.log_enricher`.
  Beyla also uses it to enter other network namespaces, so context propagation works for connections opened before instrumentation.

When `CAP_SYS_ADMIN` is present, Beyla skips the startup checks for all other capabilities.
The kernel doesn't grant `CAP_NET_RAW` or `CAP_SYS_PTRACE` through `CAP_SYS_ADMIN`, so Beyla doesn't report a missing one at startup.

Kernels earlier than 5.8, such as the RHEL 8 kernel 4.18, don't have `CAP_BPF` or `CAP_PERFMON`, so `CAP_SYS_ADMIN` covers those operations.
On these kernels, the Beyla startup check only looks for `CAP_SYS_ADMIN`.
`CAP_SYS_ADMIN` doesn't replace `CAP_NET_RAW` or `CAP_SYS_PTRACE`, so grant those too for the features that use them.
For the supported kernel versions, refer to [Beyla requirements and limitations][requirements].

## Startup capability check

When Beyla starts, it checks for the capabilities that the features in its configuration need.
If any are missing, Beyla logs a warning, for example:

```text
time=2025-01-27T17:21:20.197-06:00 level=WARN msg="Required system capabilities not present, Beyla may malfunction" error="the following capabilities are required: CAP_DAC_READ_SEARCH, CAP_BPF, CAP_CHECKPOINT_RESTORE"
```

Beyla then attempts to continue running, but missing capabilities may lead to errors later on.

To make Beyla exit when required capabilities are missing, set `BEYLA_ENFORCE_SYS_CAPS=1`, or `enforce_sys_caps: true` in the configuration file.
Beyla then logs the missing capabilities as an error and exits.
For details, refer to [System capabilities][system-capabilities].

## Kernel `perf_event_paranoid` setting

The `kernel.perf_event_paranoid` kernel setting controls access to performance monitoring for processes that don't have `CAP_PERFMON`.
In the upstream kernel, `CAP_PERFMON` bypasses these checks, and the default value is `2`.
You can change the setting with `sysctl` or by writing to the file `/proc/sys/kernel/perf_event_paranoid`.
The `perf_event_paranoid` section in the [kernel documentation][kernel-sysctl] describes this setting, and [the perf-security documentation][perf-security] covers it more comprehensively.

Some Linux distributions define higher levels for `kernel.perf_event_paranoid`, for example Debian-based distributions [also use][lwn-paranoid] `kernel.perf_event_paranoid=3`, which disallows access to `perf_event_open()` without `CAP_SYS_ADMIN`.
If you are running on a distribution with `kernel.perf_event_paranoid` setting higher than `2`, you can either modify your configuration to lower it to `2` or use `CAP_SYS_ADMIN` instead of `CAP_PERFMON`.

To check the current value, run the following command on a host or node:

```sh
sysctl kernel.perf_event_paranoid
```

### Managed Kubernetes nodes

Both AKS and EKS environments come with kernels that by default set `kernel.perf_event_paranoid` higher than `1`.
If your nodes set it higher than `2`, grant Beyla `CAP_SYS_ADMIN` or set the value to `2` on each node.

To change the value, use the node configuration method of your platform:

- **Amazon EKS with Bottlerocket nodes**: Set `kernel.perf_event_paranoid` in the `bottlerocket.settings` field of the `eksctl` node group. Refer to the [`eksctl` Bottlerocket example][eksctl-bottlerocket] and [Bottlerocket kernel settings][bottlerocket-kernel].
- **EKS Anywhere with Bottlerocket nodes**: Set `hostOSConfiguration.bottlerocketConfiguration.kernel.sysctlSettings` in the machine configuration, and run `eksctl anywhere create cluster -f <CLUSTER_FILE>`, where _`<CLUSTER_FILE>`_ is your cluster specification file. Refer to [EKS Anywhere host OS configuration][eksa-hostos].
- **AKS**: The AKS custom node configuration doesn't support `kernel.perf_event_paranoid`. For settings outside the supported list, AKS recommends a DaemonSet. Refer to [Customize node configuration for AKS node pools][aks-node-config].

## Grant capabilities

How you grant capabilities to Beyla depends on how you deploy it:

- **Beyla binary on a host**: Set file capabilities with `setcap`. Refer to [`setcap` examples][setcap-examples].
- **Docker**: [Container requirements][docker-requirements]
- **Kubernetes manifests**: [Deploy Beyla unprivileged][k8s-unprivileged]
- **Beyla Helm chart**: [Reduce Beyla privileges][helm-privileges]

## `setcap` examples

The following examples grant the capabilities for one feature to a Beyla binary and start Beyla.
On kernels earlier than 5.11, also add `cap_sys_resource` to each `setcap` command.

### Application observability

```sh
sudo setcap cap_bpf,cap_checkpoint_restore,cap_dac_read_search,cap_net_raw,cap_perfmon,cap_sys_ptrace+ep ./bin/beyla
BEYLA_OPEN_PORT=8080 BEYLA_TRACE_PRINTER=text ./bin/beyla
```

### Application observability with trace context propagation

```sh
sudo setcap cap_bpf,cap_dac_read_search,cap_checkpoint_restore,cap_perfmon,cap_net_raw,cap_net_admin,cap_sys_ptrace,cap_sys_admin+ep ./bin/beyla
BEYLA_BPF_CONTEXT_PROPAGATION=all BEYLA_OPEN_PORT=8080 BEYLA_TRACE_PRINTER=text ./bin/beyla
```

### Network observability with the `socket_filter` source

```sh
sudo setcap cap_bpf,cap_net_raw,cap_perfmon+ep ./bin/beyla
BEYLA_NETWORK_METRICS=1 BEYLA_NETWORK_PRINT_FLOWS=1 ./bin/beyla
```

The network examples use the deprecated `BEYLA_NETWORK_METRICS` variable, because it's the only way to print network flows without a metrics exporter.

### Network observability with the `tc` source

```sh
sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep ./bin/beyla
BEYLA_NETWORK_METRICS=1 BEYLA_NETWORK_PRINT_FLOWS=1 BEYLA_NETWORK_SOURCE=tc ./bin/beyla
```

### TCP statistics

This example starts Beyla with the Prometheus exporter on port `9400`:

```sh
sudo setcap cap_bpf,cap_net_raw,cap_perfmon,cap_sys_ptrace+ep ./bin/beyla
BEYLA_METRICS_FEATURES=stats BEYLA_PROMETHEUS_PORT=9400 ./bin/beyla
```

## Internal eBPF tracer capability requirement reference

Beyla uses *tracers*, a set of eBPF programs that implement the underlying functionality.
A tracer may load and use different kinds of eBPF programs, each requiring their own set of capabilities.

The following list maps each internal tracer to their required capabilities, intended to serve as a reference for developers, contributors, and those interested in the internals of Beyla:

**(Network observability) Socket flow fetcher:**

- `CAP_BPF`: for `BPF_PROG_TYPE_SOCK_FILTER`
- `CAP_NET_RAW`: to create `AF_PACKET` socket and attaching socket filters to a network interface
- `CAP_PERFMON`

**(Network observability) Flow fetcher (tc):**

- `CAP_BPF`
- `CAP_NET_ADMIN`: for loading `PROG_TYPE_SCHED_CLS` eBPF TC programs, used for inspecting network traffic
- `CAP_PERFMON`: for direct access to packet memory via `struct __sk_buff::data` and to allow pointer arithmetic in eBPF programs

**(Application observability) Watcher:**

- `CAP_BPF`
- `CAP_CHECKPOINT_RESTORE`
- `CAP_DAC_READ_SEARCH`: to bypass file read, and directory read and execute, permission checks
- `CAP_PERFMON`: for loading `BPF_PROG_TYPE_KPROBE` eBPF programs that require pointer arithmetic

**(Application observability) Support for all programming languages:**

- `CAP_BPF`
- `CAP_DAC_READ_SEARCH`
- `CAP_CHECKPOINT_RESTORE`
- `CAP_PERFMON`
- `CAP_NET_RAW`: to create `AF_PACKET` socket used to attach `obi_socket__http_filter` to network interfaces
- `CAP_SYS_PTRACE`: for access to `/proc/pid/exe` and other nodes in `/proc`
- `CAP_SYS_ADMIN`: optional, for Go library-level trace context propagation, log injection, and entering other network namespaces

[export-features]: ../../configure/export-data/#metrics-export-features
[requirements]: ../requirements/
[system-capabilities]: ../../configure/options/#system-capabilities
[lockdown]: ../../traces/#kernel-integrity-mode-limitations
[docker-requirements]: ../../setup/docker/#container-requirements
[k8s-unprivileged]: ../../setup/kubernetes/#deploy-beyla-unprivileged
[helm-privileges]: ../../setup/kubernetes-helm/#reduce-beyla-privileges
[capabilities-man]: https://man7.org/linux/man-pages/man7/capabilities.7.html
[service-discovery]: ../../configure/service-discovery/
[network-config]: ../../network/config/
[context-propagation]: ../../configure/controlling-instrumentation/#enable-context-propagation
[setcap-examples]: #setcap-examples
[kernel-sysctl]: https://docs.kernel.org/admin-guide/sysctl/kernel.html#perf-event-paranoid
[perf-security]: https://docs.kernel.org/admin-guide/perf-security.html
[lwn-paranoid]: https://lwn.net/Articles/696216/
[eksctl-bottlerocket]: https://github.com/eksctl-io/eksctl/blob/main/examples/20-bottlerocket.yaml
[bottlerocket-kernel]: https://bottlerocket.dev/en/os/latest/#/api/settings/kernel/
[eksa-hostos]: https://anywhere.eks.amazonaws.com/docs/getting-started/optional/hostosconfig/
[aks-node-config]: https://learn.microsoft.com/en-us/azure/aks/custom-node-configuration?tabs=linux-node-pools
