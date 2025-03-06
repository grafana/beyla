---
title: Network metrics
menuTitle: Network
description: Configuring Beyla to observe point-to-point network metrics.
weight: 3
keywords:
  - Beyla
  - eBPF
  - Network
---

# Network metrics

Grafana Beyla can be configured to provide network metrics between different endpoints. For example, between physical nodes, containers, Kubernetes pods, services, etc.

## Get started

To get started using Beyla networking metrics, consult the [quickstart setup documentation]({{< relref "./quickstart" >}}), and for advanced configuration, consult the [configuration documentation]({{< relref "./config" >}}).

## Metric attributes

Beyla provides two families of network metrics:

* **Network flow bytes** as the number of bytes observed between two network endpoints.
  - `beyla.network.flow.bytes`, if it is exported via OpenTelemetry.
  - `beyla_network_flow_bytes_total`, if it is exported by a Prometheus endpoint.
  - To enable it, add the `network` option to the [BEYLA_OTEL_METRICS_FEATURES or BEYLA_PROMETHEUS_FEATURES]({{< relref "../configure/export-data.md" >}}) configuration option.
* **Inter-zone bytes** as the number of bytes observed between two network endpoints in different Cloud Availability Zones.
  - `beyla.network.inter.zone.bytes`, if it is exported via OpenTelemetry.
  - `beyla_network_inter_zone_bytes_total`, if it is exported by a Prometheus endpoint.
  - More information about how to enable it in the [Measuring traffic between Cloud availability zones]({{< relref "./inter-az.md" >}}) documentation.

Network metric can have the attributes in the following table.

By default, only the following attributes are reported for network flow bytes: `k8s.src.owner.name`, `k8s.src.namespace`, `k8s.dst.owner.name`, `k8s.dst.namespace`, and `k8s.cluster.name`.

For the inter-zone bytes metric, the default attributes are `k8s.cluster.name`, `src.zone` and `dst.zone`.

| Attribute name (OpenTelemetry / Prometheus) | Description                                                                                                                                                                         |
|---------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `beyla.ip` / `beyla_ip`                     | Local IP address of the Beyla instance that emitted the metric                                                                                                                      |
| `transport`                                 | L4 Transport protocol (for example, `TCP` or `UDP`)                                                                                                                                 |
| `src.address` / `src_address`               | Source IP address of Network flow                                                                                                                                                   |
| `dst.address` / `dst_address`               | Destination IP address of Network flow
| `src.port` / `src_port`                     | Source port of Network flow                                                                                                                                                         |
| `dst.port` / `dst_port`                     | Destination port of Network flow                                                                                                                                                    |
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
| `src.zone` / `src_zone`                     | Name of the source Cloud Availability Zone                                                                                                                                          |
| `dsg.zone` / `dst_zone`                     | Name of the destination Cloud Availability Zone                                                                                                                                     |

### How to specify reported attributes

If the metric with all the possible attributes is reported it might lead to a cardinality explosion, especially when including external traffic in the `src.address`/`dst.address` attributes.

You can specify which attributes are allowed in the Beyla configuration, to aggregate the metric by them.

For example:

```yaml
network:
  enable: true
attributes:
  kubernetes:
    enable: true
  select:
    beyla_network_flow_bytes:
      include:
        - k8s.src.owner.name
        - k8s.src.namespace
        - k8s.dst.owner.name
        - k8s.dst.namespace
        - k8s.cluster.name
```

In this example, the bytes metric is the aggregated by the source and destination owners. This is, all the
pods from a given Deployment/StatefulSet/ReplicaSet/DaemonSet.

For more information about the `attributes.select` section, check the [Configuration options]({{< relref "../configure/options" >}}).
