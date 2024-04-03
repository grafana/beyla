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

## Get started

To get started using Beyla networking metrics, consult the [quickstart setup documentation]({{< relref "./quickstart" >}}), and for advanced configuration, consult the [configuration documentation]({{< relref "./config" >}}).

## Metric attributes

Network metrics provides a single metric:

- `beyla.network.flow.bytes`, if it is exported via OpenTelemetry.
- `beyla_network_flow_bytes_total`, if it is exported by a Prometheus endpoint.

The metric represents a counter of the Number of bytes observed between two network endpoints, and can have the attributes in the following table.

By default, only the following attributes are reported: `k8s.src.owner.name`, `k8s.src.namespace`, `k8s.dst.owner.name`, `k8s.dst.namespace`, and `k8s.cluster.name`.

| Attribute name (OpenTelemetry / Prometheus) | Description                                                                                                                                                                         |
|---------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `beyla.ip` / `beyla_ip`                     | Local IP address of the Beyla instance that emitted the metric                                                                                                                      |
| `src.address` / `src_address`               | Source IP address of Network flow                                                                                                                                                   |
| `dst.address` / `dst_address`               | Destination IP address of Network flow                                                                                                                                              |
| `src.name` / `src_name`                     | Name of Network flow source: Kubernetes name, host name, or IP address                                                                                                              |
| `dst.name` / `dst_name`                     | Name of Network flow destination: Kubernetes name, host name, or IP address                                                                                                         |
| `src.cidr` / `src_cidr`                     | If the [`cidrs` configuration section]({{< relref "./config" >}}) is set, the CIDR that matches the source IP address                                                               |
| `dst.cidr` / `dst_cidr`                     | If the [`cidrs` configuration section]({{< relref "./config" >}}) is set, the CIDR that matches the destination IP address                                                          |
| `k8s.src.namespace` / `k8s_src_namespace`   | Kubernetes namespace of the source of the flow                                                                                                                                      |
| `k8s.dst.namespace` / `k8s_dst_namespace`   | Kubernetes namespace of the destination of the flow                                                                                                                                 |
| `k8s.src.name` / `k8s_src_name`             | Name of the source Pod, Service, or Node                                                                                                                                            |
| `k8s.dst.name` / `k8s_dst_name`             | Name of the destination Pod, Service, or Node                                                                                                                                       |
| `k8s.src.type` / `k8s_src_type`             | Type of the source: `Pod`, `Node`, or `Service`                                                                                                                                     |
| `k8s.dst.type` / `k8s_dst_type`             | Type of the destination: `Pod`, `Node`, or `Service`                                                                                                                                |
| `k8s.src.owner.name` / `k8s_src_owner_name` | Name of the owner of the source Pod. If there is no owner, the Pod name is used                                                                                                     |
| `k8s.dst.owner.name` / `k8s_dst_owner_name` | Name of the owner of the destination Pod. If there is no owner, the Pod name is used                                                                                                |
| `k8s.src.owner.type` / `k8s_src_owner_type` | Type of the owner of the source Pod: `Deployment`, `DaemonSet`, `ReplicaSet`, `StatefulSet`, or `Pod` if there is no owner                                                          |
| `k8s.dst.owner.type` / `k8s_dst_owner_type` | Type of the owner of the destination Pod: `Deployment`, `DaemonSet`, `ReplicaSet`, `StatefulSet`, or `Pod` if there is no owner                                                     |
| `k8s.src.node.ip` / `k8s_src_node_ip`       | IP address of the source Node                                                                                                                                                       |
| `k8s.dst.node.ip` / `k8s_dst_node_ip`       | IP address of the destination Node                                                                                                                                                  |
| `k8s.src.node.name` / `k8s_src.node_name`   | Name of the source Node                                                                                                                                                             |
| `k8s.dst.node.name` / `k8s_dst.node_name`   | Name of the destination Node                                                                                                                                                        |
| `k8s.cluster.name` / `k8s_cluster_name`     | Name of the Kubernetes cluster. Beyla can auto-detect it on Google Cloud, Microsoft Azure, and Amazon Web Services. For other providers, set the `BEYLA_KUBE_CLUSTER_NAME` property |

### How to specify reported attributes

If the metric with all the possible attributes is reported it might lead to a cardinality explosion, especially when including external traffic in the `src.address`/`dst.address` attributes.

You can specify which attributes are allowed in the Beyla configuration, to aggregate the metric by them.

For example:

```yaml
network:
  enable: true
  allowed_attributes:
    - k8s.src.owner.name
    - k8s.src.namespace
    - k8s.dst.owner.name
    - k8s.dst.namespace
    - k8s.cluster.name
```

In this example, the bytes metric is the aggregated by the source and destination owners. This is, all the
pods from a given Deployment/StatefulSet/ReplicaSet/DaemonSet.
