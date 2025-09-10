---
title: Measure traffic between Cloud availability zones
menuTitle: Measure traffic between Cloud availability zones
description: How to measure the network traffic between different Cloud availability zones
weight: 1
keywords:
  - Beyla
  - eBPF
  - Network
---

# Measure traffic between Cloud availability zones

{{< admonition type="note" >}}
This feature is currently only available in Kubernetes clusters.
{{< /admonition >}}

Traffic between Cloud Availability Zones might incur additional costs. Beyla is able to measure it either by
adding `src.zone` and `dst.zone` attributes to regular network metrics,
or by providing a separate `beyla.network.inter.zone.bytes` (OTEL) / `beyla_network_inter_zone_bytes_total` (Prometheus)
metric.

## Add `src.zone` and `dst.zone` attributes to regular network metrics

Source and destination availability zone attributes are disabled by default in Beyla. To enable it, explicitly add them to the list of
included network attributes in the Beyla YAML configuration:

```
attributes:
  select:
    beyla_network_flow_bytes:
      include:
        - k8s.src.owner.name
        - k8s.src.namespace
        - k8s.dst.owner.name
        - k8s.dst.namespace
        - k8s.cluster.name
        - src.zone
        - dst.zone
```

This configuration makes inter-zone traffic visible for each `beyla_network_flow_bytes_total` metric
with different `src_zone` and `dst_zone` attributes.

If you require higher granularity in your inter-zone traffic measurement (for example, source/destination pods or nodes),
adding zone attributes would impact the cardinality of the metric, even for traffic within the same availability zone.

## Use the `beyla.network.inter.zone` metric

Using a separate metric for inter-zone traffic reduces the metric cardinality impact of collecting this data,
because the `src.zone` and `dst.zone` attributes are not added to the regular network metrics.

To enable the `beyla.network.inter.zone` metric, add the `network_inter_zone` option to the
[BEYLA_OTEL_METRICS_FEATURES or BEYLA_PROMETHEUS_FEATURES](../../configure/export-data/) configuration option,
or its equivalent YAML options. For example, if Beyla is configured to export metrics via OpenTelemetry:

```yaml
otel_metrics_export:
  features:
    - network
    - network_inter_zone
```

By default, the `beyla.network.inter.zone` metric includes only high-level attributes such as zone information and source/destination owner names to keep metric cardinality low. However, you might want to analyze inter-zone traffic at a more granular level, such as by individual pods or nodes, to identify specific sources of cross-zone communication.

To include additional attributes for detailed analysis, configure attribute selection specifically for the inter-zone metric:

```yaml
attributes:
  select:
    beyla_network_inter_zone_bytes:
      include:
        - k8s.src.namespace
        - k8s.src.pod.name
        - k8s.src.node.name
        - k8s.dst.namespace
        - k8s.dst.pod.name
        - k8s.dst.node.name
        - k8s.cluster.name
        - src.zone
        - dst.zone
```

This configuration provides detailed visibility into which specific pods and nodes generate inter-zone traffic, helping you optimize your application topology and reduce cross-zone costs.

{{< admonition type="note" >}}
Adding more attributes increases the metric cardinality.
{{< /admonition >}}


## PromQL queries to measure inter-zone traffic

Assuming that both `network` and `network_inter_zone` metric families are enabled, you can use the following PromQL queries
to measure inter-zone traffic:

Overall inter-zone traffic throughput:

```
sum(rate(beyla_network_inter_zone_bytes_total[$__rate_interval]))
```

Inter-zone traffic throughput, summarized by source and destination zones:
```
sum(rate(beyla_network_inter_zone_bytes_total[$__rate_interval])) by(src_zone,dst_zone)
```

Overall same-zone traffic throughput:

```
sum(rate(beyla_network_flow_bytes_total[$__rate_interval]))
  - sum(rate(beyla_network_inter_zone_bytes_total[$__rate_interval]))
```

Percentage of inter-zone traffic from the total:

```
100 * sum(rate(beyla_network_inter_zone_bytes_total[$__rate_interval]))
  / sum(rate(beyla_network_flow_bytes_total[$__rate_interval]))
```


