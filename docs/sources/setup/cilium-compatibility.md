---
title: Cilium compatibility
menuTitle: Cilium compatibility
description: Compatibility notes when running Beyla alongside Cilium
weight: 900
keywords:
  - Beyla
  - eBPF
  - distributed traces
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/cilium-compatibility/
  - ../cilium-compatibility/ # /docs/beyla/<BEYLA_VERSION>/cilium-compatibility/
---

# Cilium compatibility

[Cilium](https://cilium.io) is an open source cloud native solution for providing, securing, and observing network connectivity between workloads. In some cases the eBPF programs Cilium uses can conflict with the ePBF programs Beyla uses and lead to issues.

Beyla and Cilium use eBPF traffic control classifier programs, `BPF_PROG_TYPE_SCHED_CLS`. These programs attach to the ingress and egress data paths of the kernel networking stack. Together they form a chain of packet filters. Each packet filter is able to inspect the contents of the packet and perform operations, for example redirect or discard the packet.

Beyla programs never disrupt the flow of a packet, but Cilium changes packet flow as part of its operation. If Cilium processes packets before Beyla it can affect its ability to process packets.

## Attachment modes

Beyla uses the Traffic Control eXpress (TCX) API or the Netlink interface in the Linux Kernel to attach traffic control (TC) programs.

The TCX API is in the kernel since version 6.6 and is the preferred method to attach TC programs. It provides a linked list mechanism to attach programs to the head, middle, or tail. Beyla and Cilium auto-detect if the kernel supports TCX and use it by default.

When Beyla and Cilium use TCX they don't interfere with each other. Beyla attaches its eBPF programs to the head of the list and Cilium to the tail. TCX is the preferred operation mode when possible.

The legacy Netlink interface relies on `clsact`, [`qdiscs`](https://tldp.org/HOWTO/Traffic-Control-HOWTO/components.html), and a BPF TC filter to attach eBPF programs to network interfaces. The kernel executes filters in order of their priority, with lower numbers having higher priority, and 1 being the highest priority.

When TCX isn't available, both Beyla and Cilium use Netlink interface to install eBPF programs. If Beyla detects Cilium runs programs with priority 1, Beyla exits and displays an error. You can resolve the error by configuring Cilium to use a priority greater than 1.

Beyla also refuses to run if it's configured to use Netlink attachments and it detects Cilium uses TCX.

### Configure Cilium Netlink priority

You can configure Cilium Netlink program priority via the `bpf-filter-priority` configuration:

```shell
cilium config set bpf-filter-priority 2
```

This ensures that Beyla programs always run before Cilium programs.

### Mixed TCX and Netlink

In the scenario in which the kernel uses both TCX and Netlink attachments, TCX programs run before programs attached via the Netlink interface.

## Beyla attachment mode configuration

Refer to the [configuration documentation](/docs/beyla/latest/configure/options/), to configure Beyla TC attachment mode using the `BEYLA_BPF_TC_BACKEND` configuration option.

You can configure Cilium via its `enable-tcx` boolean configuration option, refer to the [Cilium documentation](https://docs.cilium.io/en/stable/) for more information.

```shell
cilium config set enable-tcx (true|false)
```
