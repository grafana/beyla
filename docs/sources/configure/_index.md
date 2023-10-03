---
title: Configure Beyla
menuTitle: Configure
description: Learn how to configure Beyla.
weight: 2
keywords:
  - Beyla
  - eBPF
---

![Grafana Beyla Logo](https://grafana.com/media/docs/grafana-cloud/beyla/beyla-logo-2.png)

# Configure Beyla

Beyla can be configured in the following ways:

1. By setting [configuration options]({{< relref "./options" >}}) in a number of ways.
2. By changing [export modes]({{< relref "./export-modes.md" >}}) between direct or agent mode.

For information on the metrics Beyla exports, see the [exported metrics]({{< relref "../metrics.md" >}}) documentation.

For information on profiling Beyla, see the [profiling]({{< relref "../profiling.md" >}}) documentation.

**Note**: If you will be using Beyla to generate traces, please make sure you've read our documentation section on configuring 
the [Routes Decorator]({{< relref "../configure/options#routes-decorator" >}}). Since Beyla is auto-instrumenting your application without any
special language level support, configuring the low cardinality routes decorator is very important for optimal results.

