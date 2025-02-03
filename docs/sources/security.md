---
title: Beyla security, permissions, and capabilities
menuTitle: Security
description: Privileges and capabilities required by Beyla
weight: 22
keywords:
  - Beyla
  - eBPF
  - security
  - capabilities
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/security/
---

# Beyla security, permissions, and capabilities

Beyla needs access to various Linux interfaces to instrument applications, such as reading from the `/proc` filesystem, loading eBPF programs, and managing network interface filters. Many of these operations require elevated permissions. The simplest solution is to run Beyla as `root`, however this might not work well in setups where full `root` access isn’t ideal. To address this, Beyla is designed to use only the specific Linux kernel capabilities needed for its current configuration.

## Linux kernel capabilities

Linux kernel capabilities are a fine-grained system for controlling access to privileged operations. They allow you to grant specific permissions to processes without giving them full superuser or root access, which helps improve security by adhering to the principle of least privilege. Capabilities split privileges typically associated with root into smaller privileged operations in the kernel.

Capabilities are assigned to processes and executable files. By using tools like `setcap`, administrators can assign specific capabilities to a binary, enabling it to perform only the operations it needs without running as root. For example:

```bash
sudo setcap cap_net_admin,cap_net_raw+ep myprogram
```

This example grants the `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities to `myprogram`, allowing it to manage network settings without requiring full superuser privileges.

By carefully choosing and assigning capabilities you can lower the risk of privilege escalation while still letting processes do what they need to.

## Beyla operation modes

Beyla can operate in two distinct modes: *application observability* and *network observability*. These modes are not mutually exclusive and can be used together as needed. For more details on enabling these modes, refer to the [configuration documentation](/docs/beyla/latest/configure/options/).

Beyla reads its configuration and checks for the required capabilities, if any are missing it displays a warning, for example:

```
time=2025-01-27T17:21:20.197-06:00 level=WARN msg="Required system capabilities not present, Beyla may malfunction" error="the following capabilities are required: CAP_DAC_READ_SEARCH, CAP_BPF, CAP_CHECKPOINT_RESTORE"
```

Beyla then attempts to continue running, but missing capabilities may lead to errors later on.

You can set `BEYLA_ENFORCE_SYS_CAPS=1`, which causes Beyla to fail immediately if the required capabilities are not available.

## List of capabilities required by Beyla

Beyla requires the following The following table Below is a list of capabilities and their usage in the context of Beyla

| Capability               | Usage in Beyla                                                                                                             |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `CAP_BPF`                | Enables general BPF functionality and `BPF_PROG_TYPE_SOCK_FILTER` programs                                                 |
| `CAP_NET_RAW`            | Used to create `AF_PACKET` raw sockets                                                                                     |
| `CAP_NET_ADMIN`          | Required to load `BPF_PROG_TYPE_SCHED_CLS` TC programs                                                                     |
| `CAP_PERFMON`            | Direct packet access and pointer arithmetic and loading `BPF_PROG_TYPE_KPROBE` programs                                    |
| `CAP_DAC_READ_SEARCH`    | Access to `/proc/self/mem` to determine kernel version                                                                     |
| `CAP_CHECKPOINT_RESTORE` | Access to symlinks in the `/proc` filesystem                                                                               |
| `CAP_SYS_PTRACE`         | Access to `/proc/pid/exe` and executable modules                                                                           |
| `CAP_SYS_RESOURCE`       | Increase the amount of locked memory available, **kernels < 5.11** only                                                    |
| `CAP_SYS_ADMIN`          | Library-level Go trace-context propagation via `bpf_probe_write_user()` and access to BTF data by the BPF metrics exporter |

### Performance monitoring tasks

Access to `CAP_PERFMON` is subject to `perf_events` access controls governed by the `kernel.perf_event_paranoid` kernel setting, which can adjusted via `sysctl` or by modifying the file `/proc/sys/kernel/perf_event_paranoid`. The default setting for `kernel.perf_event_paranoid` is typically `2`, which is documented under the `perf_event_paranoid` section in the [kernel documentation](https://www.kernel.org/doc/Documentation/sysctl/kernel.txt) and more comprehensively under [the perf-security documentation](https://www.kernel.org/doc/Documentation/admin-guide/perf-security.rst).

Some Linux distributions define higher levels for `kernel.perf_event_paranoid`, for example Debian based distributions [also use](https://lwn.net/Articles/696216/) `kernel.perf_event_paranoid=3`, which disallows access to `perf_event_open()` without `CAP_SYS_ADMIN`. If you are running on a distribution with `kernel.perf_event_paranoid` setting higher than `2`, you can either modify your configuration to lower it to `2` or use `CAP_SYS_ADMIN` instead of `CAP_PERFMON`.

## Example scenarios

The following example scenarios showcases how to run Beyla as a non-root user:

### Network metrics via a socket filter

Required capabilities:

* `CAP_BPF`
* `CAP_NET_RAW`

Set the required capabilities and start Beyla:

```bash
sudo setcap cap_bpf,cap_net_raw+ep ./bin/beyla
BEYLA_NETWORK_METRICS=1 BEYLA_NETWORK_PRINT_FLOWS=1 bin/beyla
```

### Network metrics via traffic control

Required capabilities:

* `CAP_BPF`
* `CAP_NET_ADMIN`
* `CAP_PERFMON`

Set the required capabilities and start Beyla:

```bash
sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep ./bin/beyla
BEYLA_NETWORK_METRICS=1 BEYLA_NETWORK_PRINT_FLOWS=1 BEYLA_NETWORK_SOURCE=tc bin/beyla
```

### Application observability

Required capabilities:

* `CAP_BPF`
* `CAP_DAC_READ_SEARCH`
* `CAP_CHECKPOINT_RESTORE`
* `CAP_PERFMON`
* `CAP_NET_RAW`
* `CAP_SYS_PTRACE`

Set the required capabilities and start Beyla:

```bash
sudo setcap cap_bpf,cap_dac_read_search,cap_perfmon,cap_net_raw,cap_sys_ptrace+ep ./bin/beyla
BEYLA_OPEN_PORT=8080 BEYLA_TRACE_PRINTER=text bin/beyla
```

### Application observability with trace context propagation

Required capabilities:

* `CAP_BPF`
* `CAP_DAC_READ_SEARCH`
* `CAP_CHECKPOINT_RESTORE`
* `CAP_PERFMON`
* `CAP_NET_RAW`
* `CAP_SYS_PTRACE`
* `CAP_NET_ADMIN`

Set the required capabilities and start Beyla:

```bash
sudo setcap cap_bpf,cap_dac_read_search,cap_perfmon,cap_net_raw,cap_sys_ptrace,cap_net_admin+ep ./bin/beyla
BEYLA_BPF_ENABLE_CONTEXT_PROPAGATION=1 BEYLA_OPEN_PORT=8080 BEYLA_TRACE_PRINTER=text bin/beyla
```

## Internal eBPF tracer capability requirement reference

Beyla uses the following list of internal eBPF tracers with their required capabilities:

**Socket flow fetcher:**

* `CAP_BPF`: for `BPF_PROG_TYPE_SOCK_FILTER`
* `CAP_NET_RAW`: to create `AF_PACKET` socket

**Flow fetcher (tc):**

* `CAP_BPF`
* `CAP_NET_ADMIN`: for `PROG_TYPE_SCHED_CLS`
* `CAP_PERFMON`: for direct access to `struct __sk_buff::data` and pointer arithmetic

**Watcher:**

* `CAP_BPF`
* `CAP_CHECKPOINT_RESTORE`
* `CAP_DAC_READ_SEARCH`: for access to `/proc/self/mem` to determine kernel version
* `CAP_PERFMON`: for `BPF_PROG_TYPE_KPROBE`

**Generic tracer:**

* `CAP_BPF`
* `CAP_DAC_READ_SEARCH`
* `CAP_CHECKPOINT_RESTORE`
* `CAP_PERFMON`
* `CAP_NET_RAW`: to create `AF_PACKET` socket used by `beyla_socket__http_filter`
* `CAP_SYS_PTRACE`: for access to `/proc/pid/exe` and other nodes in `/proc`

**TC tracers:**

* `CAP_BPF`
* `CAP_DAC_READ_SEARCH`
* `CAP_PERFMON`
* `CAP_NET_ADMIN`: for `BPF_PROG_TYPE_SCHED_CLS`, `BPF_PROG_TYPE_SOCK_OPS` and `BPF_PROG_TYPE_SK_MSG`

**GO tracer:**

* `CAP_BPF`
* `CAP_DAC_READ_SEARCH`
* `CAP_CHECKPOINT_RESTORE`
* `CAP_PERFMON`
* `CAP_NET_RAW`: to create `AF_PACKET` socket used by `beyla_socket__http_filter`
* `CAP_SYS_PTRACE`: for access to `/proc/pid/exe` and other nodes in `/proc`
* `CAP_SYS_ADMIN`: for probe based (`bpf_probe_write_user()`) library level context propagation
