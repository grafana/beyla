---
title: Network Metrics
menuTitle: Network
description: Configuring Beyla to observe point-to-point network metrics.
weight: 1
keywords:
  - Beyla
  - eBPF
  - Network
---

# Network Metrics

Grafana Beyla can be configured to provide network metrics between different endpoints (physical nodes,
containers, Kubernetes pods and services, etc.).

> ⚠️ This is an unstable, under-development feature and might be subject to breaking changes in
> the short term. Use it at your own risk.

- [Beyla Network Metrics quickstart]({{< relref "./quickstart" >}})
- [Beyla Network Metrics configuration options]({{< relref "./config" >}})

This feature currently provides a single **OpenTelemetry** metric with the following attributes:

> ⚠️ Prometheus exporting for network metrics is not currently supported.

* Metric name: `beyla.network.flow.bytes`
  * Type: Counter
  * Description: total bytes sent value of network flows observed by the eBPF probe since its launch.
  * Attributes: you can selectively select which attributes to show, to reduce cardinality.
    * `beyla.ip`: the local IP of the Beyla instance that emitted the metric.
    * `src.address`/`dst.address`: source/destination IP address of the network flow.
    * `src.name`/`dst.name`: name of the network flow source/destination. It can be a Kubernetes name, a host name, or the IP address.
    * `src.namespace`/`dst.namespace`: namespace of the network flow source/destination. Might be empty in non-Kubernetes flows.
    * `src.cidr`/`dst.cidr`: if the [`cidrs` configuration section]({{< relref "./config" >}}) is set, the CIDR
      that matches the source/destination IP address, if any.
    * `k8s.src.namespace`/`k8s.dst.namespace`: Kubernetes namespace of the source/destination of the flow.
    * `k8s.src.name`/`k8s.dst.name`: name of the source/destination Pod, Service, or Node.
    * `k8s.src.owner.name`/`k8s.dst.owner.name`: name of the owner of the source/destination Pod. If it has no owner,
      it shows the name of the Pod.
    * `k8s.src.owner.type`/`k8s.dst.owner.type`: type of the owner of the source/destination Pod.
      It can be: `Deployment`, `DaemonSet`, `ReplicaSet`, `StatefulSet` or, if it has no owner, `Pod`.
    * `k8s.src.host.ip`/`k8s.dst.host.ip`: IP of the source/destination physical host.
    * `k8s.src.host.name`/`k8s.dst.host.name`: name of the source/destination physical host.
    * `k8s.cluster.name`: name of the Kubernetes cluster. Beyla can auto-detect it on Google, Azure, and
      Amazon clouds. For other providers, you might need to specify it manually with the `BEYLA_KUBE_CLUSTER_NAME`
      or this property remains empty.

Reporting the preceding metric with all the attributes might lead to a cardinality explosion
especially if you are reporting external traffic in the `src.address`/`dst.address` attributes.

Beyla allows specifying which attributes are allowed to be displayed, and aggregates
the metrics by them. For example:

```yaml
network:
  enable: true
  allowed_attributes:
    - k8s.src.owner.name
    - k8s.src.namespace
    - k8s.dst.owner.name
    - k8s.dst.namespace
```

The preceding example aggregates the bytes metrics by source and destination owners. This is, all the
pods from a given Deployment/StatefulSet/ReplicaSet/DaemonSet.