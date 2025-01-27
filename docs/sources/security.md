---
title: Security, permissions and capabilities
menuTitle: Security, permissions and capabilities
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

# Security, permissions and capabilities

Beyla needs access to various Linux interfaces to instrument applications, such as reading from the `/proc` filesystem, loading _eBPF_ programs, and managing network interface filters. Many of these operations require elevated permissions due to their nature. The simplest solution is to run Beyla as `root`, which gives it all the permissions it needs. However, this might not work well in more complex setups where full `root` access isn’t ideal. To address this, Beyla is designed to use only the specific Linux kernel capabilities needed for its current configuration.

## Linux kernel capabilities

Linux kernel capabilities are a fine-grained system for controlling access to privileged operations on the system. They allow you to grant specific permissions to processes without giving them full root (superuser) access, which helps improve security by adhering to the principle of least privilege. Instead of relying on the traditional all-or-nothing root model, capabilities split the powerful privileges typically associated with root into smaller, more manageable units.

Each capability corresponds to a particular privileged operation in the kernel.

Capabilities are assigned to processes and executable files. By using tools like `setcap`, administrators can assign specific capabilities to a binary, enabling it to perform only the operations it needs without running as `root`. For example:

```bash
sudo setcap cap_net_admin,cap_net_raw+ep myprogram
```

This example grants the `CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities to `myprogram`, allowing it to manage network settings without requiring full superuser privileges.

By choosing and assigning capabilities carefully, you can lower the risk of privilege escalation while still letting processes do what they need to.

## Beyla operation modes

Beyla can operate in two distinct modes: _application observability_ and _network observability_. These modes are not mutually exclusive and can be used together as needed. The former is typically enabled using the `BEYLA_OPEN_PORT` or `BEYLA_EXECUTABLE_NAME` options, while the latter is controlled via the `BEYLA_NETWORK_METRICS` option. For more details on enabling these modes, refer to the [configuration documentation](/docs/beyla/latest/configure/options/).

What Beyla requires in terms of capabilities depends entirely on the modes and features you enable. Conversely, the capabilities you provide determine what Beyla is able to do.

When starting up, Beyla reads its configuration and checks for the required capabilities. If any are missing, Beyla displays a warning like the following:

```
time=2025-01-27T17:21:20.197-06:00 level=WARN msg="Required system capabilities not present, Beyla may malfunction" error="the following capabilities are required: CAP_DAC_READ_SEARCH, CAP_BPF, CAP_CHECKPOINT_RESTORE"
```

Beyla then attempts to continue running, but missing capabilities may lead to errors later on.

To prevent this, you can set `BEYLA_ENFORCE_SYS_CAPS=1`, which causes Beyla to fail immediately if the required capabilities are not available. In this case, it terminates right after printing the warning message above.

## List of capabilities required by Beyla

Below is a list of capabilities and their usage in the context of Beyla

| Capability               | Usage in Beyla                                                                                                             |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| `CAP_BPF`                | enables general BPF functionality and `BPF_PROG_TYPE_SOCK_FILTER` programs                                                 |
| `CAP_NET_RAW`            | used to create `AF_PACKET` raw sockets                                                                                     |
| `CAP_NET_ADMIN`          | required to load `BPF_PROG_TYPE_SCHED_CLS` (tc) programs                                                                   |
| `CAP_PERFMON`            | direct packet access and pointer arithmetic and loading `BPF_PROG_TYPE_KPROBE` programs                                    |
| `CAP_DAC_READ_SEARCH`    | access to `/proc/self/mem` to determine kernel version                                                                     |
| `CAP_CHECKPOINT_RESTORE` | access to symlinks in the `/proc` filesystem                                                                               |
| `CAP_SYS_PTRACE`         | access to `/proc/pid/exe` and friends                                                                                      |
| `CAP_SYS_RESOURCE`       | _(kernels **< 5.11** only)_ increase the amount of locked memory available.                                                |
| `CAP_SYS_ADMIN`          | Library-level Go trace-context propagation via `bpf_probe_write_user()` and access to BTF data by the BPF metrics exporter |

**Note** Access to `CAP_PERFMON` is subject to `perf_events` access controls governed by the `kernel.perf_event_paranoid` kernel setting, which can adjusted via `sysctl` or by modifying the file `/proc/sys/kernel/perf_event_paranoid`.
The default setting for `kernel.perf_event_paranoid` is typically `2`, which is documented under the `perf_event_paranoid` section in the [kernel documentation](https://www.kernel.org/doc/Documentation/sysctl/kernel.txt) and more comprehensively under [the perf-security documentation](https://www.kernel.org/doc/Documentation/admin-guide/perf-security.rst).
Some Linux distributions define higher levels for `kernel.perf_event_paranoid`, for example Debian based distributions [also use](https://lwn.net/Articles/696216/) `kernel.perf_event_paranoid=3`,
which disallows access to `perf_event_open()` without `CAP_SYS_ADMIN`. If you are running on a distribution with `kernel.perf_event_paranoid` setting higher than `2`,
you can either modify your configuration to lower it to `2` or use `CAP_SYS_ADMIN` instead of `CAP_PERFMON`.

## Examples

The final set of required capabilities depends on the actual Beyla configuration and the type of tracers being used, as described in the section  __Beyla operation modes__ above. Here are a few examples of how to run Beyla as a non-root user.

### Network Metrics (using a socket filter)

#### Required capabilities:
* `CAP_BPF`
* `CAP_NET_RAW`

```
sudo setcap cap_bpf,cap_net_raw+ep ./bin/beyla
BEYLA_NETWORK_METRICS=1 BEYLA_NETWORK_PRINT_FLOWS=1 bin/beyla
```

### Network Metrics (using traffic control)

#### Required capabilities:
* `CAP_BPF`
* `CAP_NET_ADMIN`
* `CAP_PERFMON`

```
sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep ./bin/beyla
BEYLA_NETWORK_METRICS=1 BEYLA_NETWORK_PRINT_FLOWS=1 BEYLA_NETWORK_SOURCE=tc bin/beyla
```

### Application observability

#### Required capabilities:
* `CAP_BPF`
* `CAP_DAC_READ_SEARCH`
* `CAP_CHECKPOINT_RESTORE`
* `CAP_PERFMON`
* `CAP_NET_RAW`
* `CAP_SYS_PTRACE`

```
sudo setcap cap_bpf,cap_dac_read_search,cap_perfmon,cap_net_raw,cap_sys_ptrace+ep ./bin/beyla
BEYLA_OPEN_PORT=8080 BEYLA_TRACE_PRINTER=text bin/beyla 
```

### Application observability with trace context propagation

#### Required capabilities:
* `CAP_BPF`
* `CAP_DAC_READ_SEARCH`
* `CAP_CHECKPOINT_RESTORE`
* `CAP_PERFMON`
* `CAP_NET_RAW`
* `CAP_SYS_PTRACE`
* `CAP_NET_ADMIN`

```
sudo setcap cap_bpf,cap_dac_read_search,cap_perfmon,cap_net_raw,cap_sys_ptrace,cap_net_admin+ep ./bin/beyla
BEYLA_BPF_ENABLE_CONTEXT_PROPAGATION=1 BEYLA_OPEN_PORT=8080 BEYLA_TRACE_PRINTER=text bin/beyla 
```

## Internal eBPF tracer capability requirement reference

Below is a list of internal eBPF tracers used by Beyla and their required capabilities
### Socket flow fetcher
- `CAP_BPF` -> for `BPF_PROG_TYPE_SOCK_FILTER`
- `CAP_NET_RAW` -> for creating `AF_PACKET` socket

### Flow fetcher (tc)
- `CAP_BPF` 
- `CAP_NET_ADMIN` -> for `PROG_TYPE_SCHED_CLS`
- `CAP_PERFMON` -> direct access to `struct __sk_buff::data` and pointer arithmetic

### Watcher
- `CAP_BPF`
- `CAP_CHECKPOINT_RESTORE`
- `CAP_DAC_READ_SEARCH` -> access to `/proc/self/mem` to determine kernel version
- `CAP_PERFMON` -> for `BPF_PROG_TYPE_KPROBE`

### Generic tracer
- `CAP_BPF`
- `CAP_DAC_READ_SEARCH`
- `CAP_CHECKPOINT_RESTORE`
- `CAP_PERFMON`
- `CAP_NET_RAW` -> for creating `AF_PACKET` socket used by `beyla_socket__http_filter`
- `CAP_SYS_PTRACE` -> access to `/proc/pid/exe` and other nodes in `/proc`

### TC tracers
* `CAP_BPF`
* `CAP_DAC_READ_SEARCH`
* `CAP_PERFMON`
* `CAP_NET_ADMIN` -> for `BPF_PROG_TYPE_SCHED_CLS`, `BPF_PROG_TYPE_SOCK_OPS` and `BPF_PROG_TYPE_SK_MSG`

### GO tracer
- `CAP_BPF`
- `CAP_DAC_READ_SEARCH`
- `CAP_CHECKPOINT_RESTORE`
- `CAP_PERFMON`
- `CAP_NET_RAW` -> for creating `AF_PACKET` socket used by `beyla_socket__http_filter`
- `CAP_SYS_PTRACE` -> access to `/proc/pid/exe` and other nodes in `/proc`
- `CAP_SYS_ADMIN` -> for probe based (`bpf_probe_write_user()`) library level context propagation


