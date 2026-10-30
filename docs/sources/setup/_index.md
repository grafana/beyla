---
title: Set up Beyla
menuTitle: Set up
description: Learn how to set up and run Beyla.
weight: 300
keywords:
  - Beyla
  - eBPF
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/setup/
---

# Set up Beyla

You can run Grafana Beyla as a Docker container, or in Kubernetes with a Helm chart or your own manifests.
Before you set up Beyla, check the [requirements and limitations][requirements].

{{< section menuTitle="true" withDescriptions="true" >}}

For configuration options and data export modes, refer to [Configure Beyla][configure].
By default, Beyla groups URL paths into routes with the `low-cardinality` routes decorator.
To define route patterns for your application, refer to [Configure Beyla routes decorator][routes].

[requirements]: ../introduction/requirements/
[configure]: ../configure/
[routes]: ../configure/routes-decorator/
