---
title: Set up Beyla
menuTitle: Set up
description: Learn how to set up and run Beyla.
weight: 1
keywords:
  - Beyla
  - eBPF
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/setup/
---

![Grafana Beyla Logo](https://grafana.com/media/docs/grafana-cloud/beyla/beyla-logo-2.png)

# Set up Beyla

There are different options to set up and run Beyla:

1. [With Docker to instrument a process running in a container](docker/).
1. [As a Kubernetes DaemonSet using Helm](kubernetes-helm/)
1. [As a Kubernetes DaemonSet the Grafana Alloy Helm chart](helm-alloy/)
1. [As a Kubernetes DaemonSet or as a sidecar container (manual process)](kubernetes/)

For information on configuration options and data export modes, see the [Configure Beyla](../configure/) documentation.

You can run Beyla as a standalone process. This approach is suitable for running with bare metal installations, in virtual machines, for local development, or advanced use cases. Consult the documentation in the [Git repository](https://github.com/grafana/beyla/blob/main/docs/sources/setup/standalone.md) to learn how to set up Beyla as a standalone process.

**Note**: If you will be using Beyla to generate traces, please make sure you've read our documentation section on configuring
the [Routes Decorator](../configure/routes-decorator/). Since Beyla is auto-instrumenting your application without any
special language level support, configuring the low cardinality routes decorator is very important for optimal results.
