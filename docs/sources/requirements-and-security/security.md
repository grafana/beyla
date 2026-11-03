---
title: Beyla security, permissions, and capabilities
menuTitle: Security
description: Learn which Linux capabilities and permissions Grafana Beyla needs, and how to run Beyla without root access.
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
The simplest solution is to run Beyla as root, however this might not work well in setups where full root access isn't ideal.
To address this, Beyla uses only the Linux kernel capabilities that its current configuration needs.

## Linux kernel capabilities

Linux kernel capabilities are a fine-grained system for controlling access to privileged operations.
They allow you to grant specific permissions to processes without giving them full superuser or root access, which helps improve security by adhering to the principle of least privilege.
Capabilities split privileges typically associated with root into smaller privileged operations in the kernel.

Capabilities apply to processes and executable files.
By using tools like `setcap`, administrators can assign specific capabilities to a binary, enabling it to perform only the operations it needs without running as root.
For example:

```sh
sudo setcap cap_net_admin,cap_net_raw+ep myprogram
```

This example grants the `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities to `myprogram`, allowing it to manage network settings without requiring full superuser privileges.

By carefully choosing and assigning capabilities you can lower the risk of privilege escalation while still letting processes do what they need to.

Refer to the [capabilities manual page][capabilities-man] for more information.

## Beyla operation modes

Beyla can operate in two distinct modes: *application observability* and *network observability*.
These modes aren't mutually exclusive, and you can use both together.
For more details on enabling these modes, refer to the [configuration documentation][configure-options].

Beyla can also collect TCP statistics metrics.
In addition to `CAP_BPF`, they need `CAP_SYS_PTRACE`, `CAP_PERFMON`, and `CAP_NET_RAW`.
To enable them, refer to [Metrics export features][export-features].

Beyla reads its configuration and checks for the required capabilities, if any are missing it displays a warning, for example:

```text
time=2025-01-27T17:21:20.197-06:00 level=WARN msg="Required system capabilities not present, Beyla may malfunction" error="the following capabilities are required: CAP_DAC_READ_SEARCH, CAP_BPF, CAP_CHECKPOINT_RESTORE"
```

Beyla then attempts to continue running, but missing capabilities may lead to errors later on.

You can set `BEYLA_ENFORCE_SYS_CAPS=1`, which causes Beyla to fail immediately if the required capabilities aren't available.

You can also set `enforce_sys_caps: true` in the configuration file.
For details, refer to [System capabilities][system-capabilities].

## List of capabilities required by Beyla

Beyla requires the following list of capabilities for its functionality:

| Capability               | Usage in Beyla                                                                                                                                                                                                                    |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CAP_BPF`                | Required in all modes on kernels 5.8 and later. Enables general BPF functionality and socket filter programs, used for capturing network flows in *network observability mode*.                                                                     |
| `CAP_NET_RAW`            | Used to create `AF_PACKET` raw sockets, which Beyla uses to attach socket filter programs. Required for *network observability* with the `socket_filter` source, for *application observability*, and for TCP statistics.                                                            |
| `CAP_NET_ADMIN`          | Required to load `BPF_PROG_TYPE_SCHED_CLS` TC programs. Beyla needs it when `network.source` is `tc` or when you enable any trace context propagation mode.                                 |
| `CAP_PERFMON`            | Used for trace context propagation, general *application observability* and network flow monitoring. Allows direct packet access by TC programs, loading eBPF probes in the kernel and pointer arithmetic used by these programs. |
| `CAP_DAC_READ_SEARCH`    | Bypasses file read, and directory read and execute, permission checks. Beyla checks for it at startup when you enable *application observability*. |
| `CAP_CHECKPOINT_RESTORE` | Access to symlinks in the `/proc` filesystem, used by Beyla to obtain various process and system information.                                                                                                                     |
| `CAP_SYS_PTRACE`         | Access to `/proc/pid/exe` and executable modules, used by Beyla to scan executable symbols and instrument different parts of a program.                                                                                           |
| `CAP_SYS_RESOURCE`       | Increase the amount of locked memory available, **kernels < 5.11** only                                                                                                                                                           |
| `CAP_SYS_ADMIN`          | Required for Go library-level trace context propagation on kernels 5.10 and later, which doesn't work when the kernel runs in [integrity mode][lockdown], and for log injection, which you configure under `ebpf.log_enricher`. Beyla also uses it to enter other network namespaces, so context propagation works for connections opened before instrumentation. On kernels earlier than 5.8, it's the only capability Beyla accepts. When it's present, Beyla skips the startup checks for all other capabilities. |

Kernels earlier than 5.8, such as the RHEL 8 kernel 4.18, require `CAP_SYS_ADMIN` instead of the other capabilities in this table.
For the supported kernel versions, refer to [Beyla requirements and limitations][requirements].

### Performance monitoring tasks

Access to `CAP_PERFMON` is subject to `perf_events` access controls governed by the `kernel.perf_event_paranoid` kernel setting, which you can adjust via `sysctl` or by modifying the file `/proc/sys/kernel/perf_event_paranoid`.
The default setting for `kernel.perf_event_paranoid` is typically `2`.
The `perf_event_paranoid` section in the [kernel documentation][kernel-sysctl] describes this setting, and [the perf-security documentation][perf-security] covers it more comprehensively.

Some Linux distributions define higher levels for `kernel.perf_event_paranoid`, for example Debian-based distributions [also use][lwn-paranoid] `kernel.perf_event_paranoid=3`, which disallows access to `perf_event_open()` without `CAP_SYS_ADMIN`.
If you are running on a distribution with `kernel.perf_event_paranoid` setting higher than `2`, you can either modify your configuration to lower it to `2` or use `CAP_SYS_ADMIN` instead of `CAP_PERFMON`.

### Deploy on AKS/EKS

Both AKS and EKS environments come with kernels that by default set `sys.perf_event_paranoid > 1`, which means Beyla needs `CAP_SYS_ADMIN` to work, refer to the section on how to [monitor task performance](#performance-monitoring-tasks) for further information. 

If you prefer to use just `CAP_PERFMON`, you can configure your node to set `kernel.perf_event_paranoid = 1`. We've provided a few examples of how to do this, keep in mind that your results may vary depending on your specific setup.

#### AKS

**Create a configuration file**

```json
{
  "sysctls": {
    "kernel.sys_paranoid": "1"
  }
}
```

**Create or update your AKS cluster**

```sh
az aks create --name myAKSCluster --resource-group myResourceGroup --linux-os-config ./linuxosconfig.json
```

For more information, see "[Customize node configuration for Azure Kubernetes Service (AKS) node pools](https://learn.microsoft.com/en-us/azure/aks/custom-node-configuration?tabs=linux-node-pools)"
#### EKS (using EKS Anywhere Configuration)

**Create a configuration file**

```yaml
apiVersion: anywhere.eks.amazonaws.com/v1alpha1
kind: VSphereMachineConfig
metadata:
  name: machine-config
spec:
  hostOSConfiguration:
    kernel:
      sysctlSettings:
        kernel.sys_paranoid: "1"
```

**Deploy or update your EKS Anywhere cluster**

```sh
eksctl create cluster --config-file hostosconfig.yaml
```

#### EKS (modifying node group settings)

**Update the node group**

```yaml
apiVersion: eks.eks.amazonaws.com/v1beta1
kind: ClusterConfig
...
nodeGroups:
  - ...
    os: Bottlerocket
    eksconfig:
      ...
      sysctls:
        kernel.sys_paranoid: "1"
```

Use the AWS Management Console, AWS CLI, or eksctl to apply the updated configuration to your EKS cluster.

For more information refer to the [EKS host OS configuration documentation](https://anywhere.eks.amazonaws.com/docs/getting-started/optional/hostosconfig/).

## Grant capabilities in containers and Kubernetes

To grant capabilities to Beyla when you deploy it in a container or in Kubernetes, refer to the section for your deployment method:

- **Docker**: [Container requirements][docker-requirements]
- **Kubernetes manifests**: [Deploy Beyla unprivileged][k8s-unprivileged]
- **Beyla Helm chart**: [Reduce Beyla privileges][helm-privileges]

## Example scenarios

The following example scenarios show how to run Beyla as a non-root user:

### Network metrics via a socket filter

Required capabilities:

- `CAP_BPF`
- `CAP_NET_RAW`
- `CAP_PERFMON`

Set the required capabilities and start Beyla:

```sh
sudo setcap cap_bpf,cap_net_raw,cap_perfmon+ep ./bin/beyla
BEYLA_NETWORK_METRICS=1 BEYLA_NETWORK_PRINT_FLOWS=1 bin/beyla
```

### Network metrics via traffic control

Required capabilities:

- `CAP_BPF`
- `CAP_NET_ADMIN`
- `CAP_PERFMON`

Set the required capabilities and start Beyla:

```sh
sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep ./bin/beyla
BEYLA_NETWORK_METRICS=1 BEYLA_NETWORK_PRINT_FLOWS=1 BEYLA_NETWORK_SOURCE=tc bin/beyla
```

### Application observability

Required capabilities:

- `CAP_BPF`
- `CAP_DAC_READ_SEARCH`
- `CAP_CHECKPOINT_RESTORE`
- `CAP_PERFMON`
- `CAP_NET_RAW`
- `CAP_NET_ADMIN`
- `CAP_SYS_ADMIN`
- `CAP_SYS_PTRACE`

Set the required capabilities and start Beyla:

```sh
sudo setcap cap_bpf,cap_dac_read_search,cap_checkpoint_restore,cap_perfmon,cap_net_raw,cap_net_admin,cap_sys_ptrace,cap_sys_admin+ep ./bin/beyla
BEYLA_BPF_CONTEXT_PROPAGATION=all BEYLA_OPEN_PORT=8080 BEYLA_TRACE_PRINTER=text bin/beyla
```

## Internal eBPF tracer capability requirement reference

Beyla uses *tracers*, a set of eBPF programs that implement the underlying functionality.
A tracer may load and use different kinds of eBPF programs, each requiring their own set of capabilities.

The list below maps each internal tracer to their required capabilities, intended to serve as a reference for developers, contributors, and those interested in the internals of Beyla:

**(Network observability) Socket flow fetcher:**

- `CAP_BPF`: for `BPF_PROG_TYPE_SOCK_FILTER`
- `CAP_NET_RAW`: to create `AF_PACKET` socket and attaching socket filters to a network interface

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
- `CAP_NET_RAW`: to create `AF_PACKET` socket used to attach `beyla_socket__http_filter` to network interfaces
- `CAP_SYS_PTRACE`: for access to `/proc/pid/exe` and other nodes in `/proc`
- `CAP_SYS_ADMIN`: for probe based library level instrumentation

[export-features]: ../../configure/export-data/#metrics-export-features
[requirements]: ../requirements/
[system-capabilities]: ../../configure/options/#system-capabilities
[lockdown]: ../../traces/#kernel-integrity-mode-limitations
[docker-requirements]: ../../setup/docker/#container-requirements
[k8s-unprivileged]: ../../setup/kubernetes/#deploy-beyla-unprivileged
[helm-privileges]: ../../setup/kubernetes-helm/#reduce-beyla-privileges
[capabilities-man]: https://man7.org/linux/man-pages/man7/capabilities.7.html
[configure-options]: ../../configure/options/
[kernel-sysctl]: https://www.kernel.org/doc/Documentation/sysctl/kernel.txt
[perf-security]: https://www.kernel.org/doc/Documentation/admin-guide/perf-security.rst
[lwn-paranoid]: https://lwn.net/Articles/696216/
