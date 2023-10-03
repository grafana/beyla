---
title: Set up Beyla
menuTitle: Setup
description: Learn how to set up and run Beyla.
weight: 1
keywords:
  - Beyla
  - eBPF
---

![Grafana Beyla Logo](https://grafana.com/media/docs/grafana-cloud/beyla/beyla-logo-2.png)

# Set up Beyla

There are different options to set up and run Beyla:

1. [As a standalone Linux process]({{< relref "./standalone.md" >}}).
2. [With Docker to instrument a process running in a container]({{< relref "./docker.md" >}}).
3. [As a Kubernetes sidecar container]({{< relref "./kubernetes.md" >}})

For information on configuration options and data export modes, see the [Configure Beyla]({{< relref "../configure/_index.md" >}}) documentation.

**Note**: If you will be using Beyla to generate traces, please make sure you've read our documentation section on configuring 
the [Routes Decorator]({{< relref "../configure/options#routes-decorator" >}}). Since Beyla is auto-instrumenting your application without any
special language level support, configuring the low cardinality routes decorator is very important for optimal results.
