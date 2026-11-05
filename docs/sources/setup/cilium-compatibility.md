---
title: Run Beyla with Cilium
menuTitle: Cilium
description: Configure Grafana Beyla and Cilium so their traffic control eBPF programs don't conflict, and fix the Cilium compatibility error at Beyla startup.
weight: 900
keywords:
  - Beyla
  - eBPF
  - Cilium
  - traffic control
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/cilium-compatibility/
  - /docs/grafana-cloud/monitor-applications/beyla/setup/cilium-compatibility/
  - ../cilium-compatibility/ # /docs/beyla/<BEYLA_VERSION>/cilium-compatibility/
---

# Run Beyla with Cilium

[Cilium][cilium] is an open source project that provides, secures, and observes network connectivity between workloads.
In some cases, the eBPF programs that Cilium uses can conflict with the eBPF programs that Grafana Beyla uses.

To prevent the conflict, configure how Beyla and Cilium attach their traffic control programs.

## Before you begin

Before you configure Beyla and Cilium, make sure you have the following:

- A Kubernetes cluster that runs Cilium, with Beyla deployed on nodes that meet the [Beyla requirements and limitations][requirements]
- `kubectl`, configured for the cluster
- For nodes that run a Linux kernel earlier than 6.6, the `cilium` CLI, with permission to change the Cilium configuration
- Access to the Beyla configuration

## Configure the attachment mode

Configure Beyla and Cilium so that Beyla programs run before Cilium programs:

1. Check whether you need to configure the attachment mode.
   Beyla attaches traffic control programs when you enable network metrics and set `network.source` to `tc`.
   Beyla also checks the Cilium programs at startup when you set `ebpf.context_propagation` to `all`, `tcp`, or `headers,tcp`.
   If your Beyla configuration uses none of these settings, you don't need to configure anything else.

1. Check the Linux kernel version of your nodes:

   ```sh
   kubectl get nodes -o wide
   ```

   The `KERNEL-VERSION` column shows the kernel version of each node.
   TCX requires Linux kernel 6.6 or later.

1. If your nodes run Linux kernel 6.6 or later, check that the Beyla `ebpf.traffic_control_backend` option or the `BEYLA_BPF_TC_BACKEND` environment variable is `auto` or `tcx`.
   The default is `auto`.
   With TCX, Beyla programs run before Cilium programs, whether Cilium uses TCX or Netlink.
   For details, refer to [Traffic control backend][tc-backend].
   If you run Beyla with the [Grafana Alloy Helm chart][alloy-helm], check the `traffic_control_backend` attribute in the `ebpf` block of the `beyla.ebpf` component instead.

1. If your nodes run a Linux kernel earlier than 6.6, set the Cilium Netlink filter priority to 2 or higher:

   ```sh
   cilium config set bpf-filter-priority 2
   ```

   Beyla attaches its Netlink filters with priority 1, so they run before Cilium filters with priority 2 or higher.
   By default, `cilium config set` restarts the Cilium Pods.

   Check that the Cilium configuration contains the new priority:

   ```sh
   cilium config view | grep bpf-filter-priority
   ```

   Keep the Beyla `ebpf.traffic_control_backend` option set to `auto` or `tc`.

1. Restart Beyla so that it runs the startup check again:

   ```sh
   kubectl rollout restart daemonset/<BEYLA_DAEMONSET> --namespace <BEYLA_NAMESPACE>
   ```

   Replace _`<BEYLA_DAEMONSET>`_ with the name of the Beyla DaemonSet, and _`<BEYLA_NAMESPACE>`_ with its namespace.
   If you run Beyla with the Alloy Helm chart, restart the Alloy DaemonSet instead.

1. Check that the Beyla Pods are running:

   ```sh
   kubectl get pods --namespace <BEYLA_NAMESPACE>
   ```

   If you run Beyla with the Alloy Helm chart, the Alloy Pods keep running even when the Cilium check fails, so check the logs in the next step.

1. Check the logs of a Beyla Pod:

   ```sh
   kubectl logs --namespace <BEYLA_NAMESPACE> <POD_NAME>
   ```

   Replace _`<POD_NAME>`_ with a Pod name from the previous command.
   If you run Beyla with the Alloy Helm chart, check the logs of an Alloy Pod.
   Alloy writes the Beyla logs to its own log, with the `source=beyla-subprocess` attribute.
   If the log doesn't contain `Cilium compatibility error`, Beyla passed the Cilium check.
   Otherwise, refer to [Troubleshoot Cilium compatibility errors][troubleshoot].

## How Beyla and Cilium share traffic control

Beyla and Cilium use eBPF traffic control classifier programs, `BPF_PROG_TYPE_SCHED_CLS`.
Beyla attaches these programs when you enable network metrics and set `network.source` to `tc`.
These programs attach to the ingress and egress data paths of the kernel networking stack.
Together they form a chain of packet filters.
Each packet filter can inspect the contents of the packet and perform operations, for example redirect or discard the packet.

Beyla programs never disrupt the flow of a packet, but Cilium changes packet flow as part of its operation.
If Cilium processes packets before Beyla, it can affect the ability of Beyla to process packets.

### Attachment modes

Beyla uses the Traffic Control eXpress (TCX) API or the Netlink interface in the Linux kernel to attach traffic control (TC) programs.

The TCX API is available in Linux kernel 6.6 and later, and is the preferred method to attach TC programs.
It provides a linked list mechanism to attach programs to the head, middle, or tail.
Beyla and Cilium auto-detect if the kernel supports TCX and use it by default.

When Beyla and Cilium use TCX, they don't interfere with each other.
Beyla attaches its eBPF programs to the head of the list and Cilium to the tail.

The legacy Netlink interface relies on `clsact`, [`qdiscs`][qdiscs], and a BPF TC filter to attach eBPF programs to network interfaces.
The kernel runs filters in order of their priority.
Filters with lower numbers run first, and 1 is the highest priority.

When TCX isn't available, both Beyla and Cilium use the Netlink interface to install eBPF programs.
If all Cilium TC filters use priority 1, Beyla exits.
For the error messages and fixes, refer to [Troubleshoot Cilium compatibility errors][troubleshoot].

Beyla also exits if you set `ebpf.traffic_control_backend` to `tc` and Cilium uses TCX.

### Mixed TCX and Netlink

When some programs attach with TCX and others with Netlink, the TCX programs run first.
If Beyla uses Netlink and Cilium uses TCX, Cilium programs run before Beyla programs, so Beyla exits.

## Troubleshoot Cilium compatibility errors

When the Cilium check fails, Beyla logs `wrong Beyla configuration` with one of the following errors and exits:

| Error | Cause | Fix |
| ----- | ----- | --- |
| `Cilium compatibility error: detected Cilium TC with priority 1 - Cilium may clobber OBI` | Beyla uses Netlink, and all Cilium TC filters use priority 1. | Set the Cilium `bpf-filter-priority` option to 2 or higher, as described in [Configure the attachment mode][configure]. On kernel 6.6 or later, you can instead set `ebpf.traffic_control_backend` to `auto` or `tcx`. |
| `Cilium compatibility error: detected Cilium TCX attachment, but OBI has been configured to use TC` | `ebpf.traffic_control_backend` is `tc`, and Cilium uses TCX. | Set `ebpf.traffic_control_backend` to `auto` or `tcx`. |

If you run Beyla with Alloy, Alloy logs `Beyla subprocess crashed, scheduling restart` and restarts Beyla.
If Cilium has priority 1 filters and filters with other priorities, Beyla logs the warning `Detected potential Cilium TC left-overs!` and keeps running.

## Next steps

- [Beyla Network Metrics configuration options][network-config]
- [Distributed traces with Beyla][traces]
- [Configure Beyla performance][tune-performance]

[cilium]: https://cilium.io
[alloy-helm]: ../helm-alloy/
[configure]: #configure-the-attachment-mode
[network-config]: ../../network/config/
[qdiscs]: https://tldp.org/HOWTO/Traffic-Control-HOWTO/components.html
[requirements]: ../../requirements-and-security/requirements/
[tc-backend]: ../../configure/tune-performance/#traffic-control-backend
[traces]: ../../traces/
[troubleshoot]: #troubleshoot-cilium-compatibility-errors
[tune-performance]: ../../configure/tune-performance/
