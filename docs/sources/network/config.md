---
title: Beyla Network Metrics configuration options
menuTitle: Configuration
description: Learn about the configuration options available for Beyla network metrics
weight: 2
keywords:
  - Beyla
  - eBPF
  - Network
---

# Beyla Network Metrics configuration options

> ⚠️ This is an unstable, under-development feature and might be subject to breaking changes in
> the short term. Use it at your own risk.

Network metrics are configured under the `network` property of the [Beyla Configuration YAML file]({{< relref "../configure/options" >}})
or with a set of environment variables prefixed as `BEYLA_NETWORK_`.

Example YAML:

```yaml
network:
  enable: true
  allowed_attributes:
    - k8s.src.owner.name
    - k8s.src.namespace
    - k8s.dst.owner.name
    - k8s.dst.namespace
    - src.cidr
    - dst.cidr
  cidrs:
    - 10.10.0.0/24
    - 10.0.0.0/8
    - 10.30.0.0/16
```

## Network metrics configuration properties

| YAML     | Environment variable    | Type    | Default |
|----------|-------------------------|---------|---------|
| `enable` | `BEYLA_NETWORK_METRICS` | boolean | `false` |

Enables network metrics reporting in Beyla.

| YAML                 | Environment variable               | Type     | Default |
|----------------------|------------------------------------|----------|---------|
| `allowed_attributes` | `BEYLA_NETWORK_ALLOWED_ATTRIBUTES` | []string | (empty) |

Specifies which attributes are visible in the metrics. Beyla aggregates the metrics
by their common visible attributes. For example, hiding the `k8s.src.name` and allowing
`k8s.src.owner.name` would aggregate the metrics of all the pods under a same owner.

This property won't filter some meta-attributes such as
`instance`, `job`, `service.instance.id`, `service_name`, `telemetry.sdk.*`, etc.

⚠️If left empty, Beyla reports all the attributes; which might increase greatly
the cardinality of your metrics. Setting this value to list only the attributes you
really need is highly recommended.

See the [Network Metrics main section]({{< relref ".." >}}) for a detailed list
of all the available attributes.

If you set this property via environment variable, each entry must be separated by a comma.
For example:

```
BEYLA_NETWORK_ALLOWED_ATTRIBUTES=src.name,dst.name
```

| YAML    | Environment variable        | Type     | Default |
|---------|-----------------------------|----------|---------|
| `cidrs` | `BEYLA_NETWORK_GROUP_CIDRS` | []string | (empty) |

CIDRs list, to be set as the `src.cidr` and `dst.cidr` attribute with the
entry that matches the `src.address` and `dst.address` respectively.

attribute as a function of the source and destination IP addresses.
If an IP does not match any address here, the attributes won't be set.
If an IP matches multiple CIDR definitions, the flow is decorated with the
narrowest CIDR. By this reason, you can safely add a 0.0.0.0/0 entry to group there
all the traffic that does not match any of the other CIDRs.

If you set this property via environment variable, each entry must be separated by a comma.
For example:

```
BEYLA_NETWORK_GROUP_CIDRS=10.0.0.0/8,192.168.0.0/16
```

| YAML       | Environment variable     | Type   | Default   |
|------------|--------------------------|--------|-----------|
| `agent_ip` | `BEYLA_NETWORK_AGENT_IP` | string | (not set) |

Allows overriding the reported `beyla.ip` attribute on each metric. If not set, Beyla
automatically detects its own IP from the specified network interface (see next property).

| YAML             | Environment variable           | Type   | Default    |
|------------------|--------------------------------|--------|------------|
| `agent_ip_iface` | `BEYLA_NETWORK_AGENT_IP_IFACE` | string | `external` |

Specifies which interface should Beyla use to pick its own IP address to set the
value of the `beyla.ip` attribute. Accepted values are: `external` (default), `local`,
or `name:<interface name>` (e.g. `name:eth0`).

If the `agent_ip` configuration property is set, this property has no effect.

| YAML            | Environment variable          | Type   | Default |
|-----------------|-------------------------------|--------|---------|
| `agent_ip_type` | `BEYLA_NETWORK_AGENT_IP_TYPE` | string | `any`   |

Specifies which type of IP address (IPv4 or IPv6 or both) should the Beyla report
in the `beyla.ip` field of each flow. Accepted values are: `any` (default), `ipv4`, `ipv6`.
If the `agent_ip` configuration property is set, this property has no effect.

| YAML         | Environment variable       | Type     | Default |
|--------------|----------------------------|----------|---------|
| `interfaces` | `BEYLA_NETWORK_INTERFACES` | []string | (empty) |

Contains the interface names from where flows are collected from. If empty, Beyla 
fetches all the interfaces in the system, excepting the ones listed in `excluded_interfaces`
(see below). If an entry is enclosed by slashes (e.g. `/br-/`), it is matched as regular expression,
otherwise it is matched as a case-sensitive string.

If you set this property via environment variable, each entry must be separated by a comma.
For example:

```
BEYLA_NETWORK_INTERFACES=eth0,eth1,/^veth/
```

| YAML                 | Environment variable               | Type     | Default |
|----------------------|------------------------------------|----------|---------|
| `exclude_interfaces` | `BEYLA_NETWORK_EXCLUDE_INTERFACES` | []string | `lo`    |

Contains the interface names to be excluded from network flow tracing. Default:
`lo` (loop-back). If an entry is enclosed by slashes (e.g. `/br-/`), it is matched as a regular expression,
otherwise it is matched as a case-sensitive string.

If you set this property via environment variable, each entry must be separated by a comma.
For example:

```
BEYLA_NETWORK_EXCLUDE_INTERFACES=lo,/^veth/
```

| YAML              | Environment variable            | Type    | Default |
|-------------------|---------------------------------|---------|---------|
| `cache_max_flows` | `BEYLA_NETWORK_CACHE_MAX_FLOWS` | integer | `5000`  |

Specifies how many flows can be accumulated in the accounting cache before
being flushed for its later export. Default value is 5000.
Decrease it if you see the "received message larger than max" error in Beyla logs.

| YAML                   | Environment variable                 | Type     | Default |
|------------------------|--------------------------------------|----------|---------|
| `cache_active_timeout` | `BEYLA_NETWORK_CACHE_ACTIVE_TIMEOUT` | duration | `5s`    |

Specifies the maximum duration that flows are kept in the accounting
cache before being flushed for its later export.

| YAML        | Environment variable      | Type   | Default |
|-------------|---------------------------|--------|---------|
| `direction` | `BEYLA_NETWORK_DIRECTION` | string | `both`  |

Allows selecting which flows to trace according to its direction in the interface
where they are captured from. Accepted values are `ingress`, `egress`, or `both` (default).

It's important to emphasize that, in this context, _ingress_ or _egress_ are not related to incoming/outgoing
traffic from outside the node or the cluster, but the network interface. This means that
the same network packet could be seen as "ingress" in a virtual network device and as "egress" in the
backing physical network interface.

| YAML       | Environment variable     | Type    | Default        |
|------------|--------------------------|---------|----------------|
| `sampling` | `BEYLA_NETWORK_SAMPLING` | integer | `0` (disabled) |

Sampling holds the rate at which packets should be sampled and sent to the target collector.
E.g. if set to 100, one out of 100 packets, on average, are sent to the target collector.


| YAML          | Environment variable        | Type    | Default |
|---------------|-----------------------------|---------|---------|
| `print_flows` | `BEYLA_NETWORK_PRINT_FLOWS` | boolean | `false` |

If set to `true`, Beyla prints each Network flow in the standard output.
It might generate a lot of output.

