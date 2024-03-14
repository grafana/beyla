---
title: Network metrics
menuTitle: Network
description: Configuring Beyla to observe point-to-point network metrics.
weight: 1
keywords:
  - Beyla
  - eBPF
  - Network
---

{{% admonition type="warning" %}}
Network metrics is an [experimental](/docs/release-life-cycle/) under development feature, expect breaking changes.
{{% /admonition %}}

# Network metrics

Grafana Beyla can be configured to provide network metrics between different endpoints. For example, between physical nodes, containers, Kubernetes pods, services, etc.

{{% admonition type="note" %}}
Prometheus exporting for network metrics is not currently supported.
{{% /admonition %}}

## Get started

To get started using Beyla networking metrics, consult the [quickstart setup documentation]({{< relref "./quickstart" >}}), and for advanced configuration, consult the [configuration documentation]({{< relref "./config" >}}).

## Metric attributes

Network metrics provides a single **OpenTelemetry** metric `beyla.network.flow.bytes`, a counter of Number of bytes observed between two network endpoints, with the following attributes:

| Attribute name       | Description                                                                                                                                                                         |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `beyla.ip`           | Local IP address of the Beyla instance that emitted the metric                                                                                                                      |
| `src.address`        | Source IP address of Network flow                                                                                                                                                   |
| `dst.address`        | Destination IP address of Network flow                                                                                                                                              |
| `src.name`           | Name of Network flow source: Kubernetes name, host name, or IP address                                                                                                              |
| `dst.name`           | Name of Network flow destination: Kubernetes name, host name, or IP address                                                                                                         |
| `src.namespace`      | Namespace of Network flow source. Could be empty in non-Kubernetes flows                                                                                                            |
| `dst.namespace`      | Namespace of Network flow destination. Could be empty in non-Kubernetes flows                                                                                                       |
| `src.cidr`           | If the [`cidrs` configuration section]({{< relref "./config" >}}) is set, the CIDR that matches the source IP address                                                               |
| `dst.cidr`           | If the [`cidrs` configuration section]({{< relref "./config" >}}) is set, the CIDR that matches the destination IP address                                                          |
| `k8s.src.namespace`  | Kubernetes namespace of the source of the flow                                                                                                                                      |
| `k8s.dst.namespace`  | Kubernetes namespace of the destination of the flow                                                                                                                                 |
| `k8s.src.name`       | Name of the source Pod, Service, or Node                                                                                                                                            |
| `k8s.dst.name`       | Name of the destination Pod, Service, or Node                                                                                                                                       |
| `k8s.src.owner.name` | Name of the owner of the source Pod. If there is no owner, the Pod name is used                                                                                                     |
| `k8s.dst.owner.name` | Name of the owner of the destination Pod. If there is no owner, the Pod name is used                                                                                                |
| `k8s.src.owner.type` | Type of the owner of the source Pod: `Deployment`, `DaemonSet`, `ReplicaSet`, `StatefulSet`, or `Pod` if there is no owner                                                          |
| `k8s.dst.owner.type` | Type of the owner of the destination Pod: `Deployment`, `DaemonSet`, `ReplicaSet`, `StatefulSet`, or `Pod` if there is no owner                                                     |
| `k8s.src.node.ip`    | IP address of the source Node                                                                                                                                                       |
| `k8s.dst.node.ip`    | IP address of the destination Node                                                                                                                                                  |
| `k8s.src.node.name`  | Name of the source Node                                                                                                                                                             |
| `k8s.dst.node.name`  | Name of the destination Node                                                                                                                                                        |
| `k8s.cluster.name`   | Name of the Kubernetes cluster. Beyla can auto-detect it on Google Cloud, Microsoft Azure, and Amazon Web Services. For other providers, set the `BEYLA_KUBE_CLUSTER_NAME` property |

### Allowed attributes

If the metric with all the attributes is reported it might lead to a cardinality explosion, especially when including external traffic in the `src.address`/`dst.address` attributes.

You can specify which attributes are allowed in the Beyla configuration. Allowed attributes and aggregates the metrics by them. For example:

```yaml
network:
  enable: true
  allowed_attributes:
    - k8s.src.owner.name
    - k8s.src.namespace
    - k8s.dst.owner.name
    - k8s.dst.namespace
```

In this example, the bytes metric is the aggregated by the source and destination owners. This is, all the
pods from a given Deployment/StatefulSet/ReplicaSet/DaemonSet.
