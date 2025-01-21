---
title: Configure Beyla metrics and traces attributes
menuTitle: Metrics attributes
description: Configure the metrics and traces attributes component that controls the attributes reported, including instance ID decoration and metadata of instrumented Kubernetes pods.
weight: 30
keywords:
  - Beyla
  - eBPF
---

# Configure Beyla metrics and traces attributes

Grafana Beyla allows configuring how some attributes for metrics and traces
are decorated. Under the `attributes` top YAML sections, you can enable
other subsections configure how some attributes are set.

The [Beyla exported metrics]({{< relref "../metrics.md" >}}) document lists the attributes
that can be reported with each metric. Some of the attributes are reported by default while
others are hidden to control the cardinality.

For each metric, you can control which attributes to see with the `select` subsection, which
is a map where each key is the name of a metric (either in its OpenTelemetry or Prometheus port),
and each metric has two more sub-properties: `include` and `exclude`.

* `include` is a list of attributes that need to be reported. Each attribute can be an attribute
  name or a wildcard (for example, `k8s.dst.*` to include all the attributes starting with `k8s.dst`).
  If no `include` list is provided, the default attribute set is reported (check [Beyla exported metrics]({{< relref "../metrics.md" >}})
  for more information about the default attributes for a given metric).
* `exclude` is a list to of attribute names/wildcards containing the attributes to remove from the
  `include` list (or the default attribute set).

Example:
```yaml
attributes:
  select:
    beyla_network_flow_bytes:
      # limit the beyla_network_flow_bytes attributes to only the three attributes
      include:
        - beyla.ip
        - src.name
        - dst.port
    sql_client_duration:
      # report all the possible attributes but db_statement
      include: ["*"]
      exclude: ["db_statement"]
    http_client_request_duration:
      # report the default attribute set but exclude the Kubernetes Pod information
      exclude: ["k8s.pod.*"]
```

Additionally, you can use "`*`" wildcards as metric names to add and exclude attributes for
groups of metrics having the same name. For example:

```yaml
attributes:
  select:
    http_*:
      include: ["*"]
      exclude: ["http_path", "http_route"]
    http_client_*:
      # override http_* exclusion
      include: ["http_path"]
    http_server_*:
      # override http_* exclusion
      include: ["http_route"]
```

In the previous example, all the metrics with a name starting with `http_` (or `http.`) would include all
the possible attributes but `http_path` and `http_route` (or `http.path`/`http.route`).
The `http_client_*` and `http_server_*` sections would override the base configuration, enabling the
`http_path` attribute for the HTTP client metrics and `http_route` for the HTTP server metrics.

When a metric name matches multiple definitions using wildcards, exact matches have higher precedence than wild card matches.

## Distributed traces and context propagation

| YAML                         | Environment variable                   | Type    | Default |
| ---------------------------- | -------------------------------------- | ------- | ------- |
| `enable_context_propagation` | `BEYLA_BPF_ENABLE_CONTEXT_PROPAGATION` | boolean | (true)  |

Enables injecting of the `Traceparent` header value for outgoing HTTP requests, allowing
Beyla to propagate any incoming context to downstream services. This context propagation
support works for any programming language and it's implemented by using Linux Traffic Control
(TC). Because Linux Traffic Control is sometimes used by other eBPF programs, this option 
requires that the other eBPF programs chain correctly with Beyla. For more information on 
this topic, please see our documentation related to [Cilium CNI]({{< relref "../../cilium-compatibility.md" >}}).
This context propagation support is fully compatible with any OpenTelemetry
distributed tracing library.

For TLS encrypted HTTP requests (HTTPS), the `Traceparent` header value is encoded
at TCP/IP packet level, and requires that Beyla is present on both sides of the communication.

For this option to correctly work in containerized environments (Kubernetes and Docker), the
following configuration must be specified:
- Beyla must be deployed as a `DaemonSet` with host network access (`hostNetwork: true`).
- The `/sys/fs/cgroup` path from the host must be volume mounted as local `/sys/fs/cgroup` path.
- The `CAP_NET_ADMIN` capability must be granted to the Beyla container.

gRPC and HTTP2 are not supported at the moment.

| YAML                    | Environment variable              | Type    | Default |
| ----------------------- | --------------------------------- | ------- | ------- |
| `track_request_headers` | `BEYLA_BPF_TRACK_REQUEST_HEADERS` | boolean | (false) |

Enables tracking of request headers for the purposes of processing any incoming 'Traceparent'
header values. If this option is enabled, when Beyla encounters an incoming server request with
a 'Traceparent' header value, it will use the provided 'trace id' to create its own trace spans.

This option does not have an effect on Go applications, where the 'Traceparent' field is always
processed, without additional tracking of the request headers.

Enabling this option may increase the performance overhead in high request volume scenarios.
This option is only useful when generating Beyla traces, it does not affect
generation of Beyla metrics.

## Other attributes

| YAML                    | Environment variable               | Type     | Default |
| ----------------------- | ---------------------------------- | -------- | ------- |
| `heuristic_sql_detect`   | `BEYLA_HEURISTIC_SQL_DETECT`      | boolean  | (false) |

By default, Beyla detects various SQL client requests through detection of their
particular binary protocol format. However, oftentimes SQL database clients send their
queries in a format where Beyla can detect the query statement without knowing
the exact binary protocol. If you are using a database technology not directly supported
by Beyla, you can enable this option to get database client telemetry. The option is
not enabled by default, because it can create false positives, for example, an application
sending SQL text for logging purposes through a TCP connection. Currently supported
protocols where this option isn't needed are the Postgres and MySQL binary protocols.

## Instance ID decoration

The metrics and the traces are decorated with a unique instance ID string, identifying
each instrumented application. By default, Beyla uses the host name that runs Beyla
(can be a container or Pod name), followed by the PID of the instrumented process;
but you can override how the instance ID is composed in the
`instance_id` YAML subsection under the `attributes` top-level section.

For example:

```yaml
attributes:
  instance_id:
    dns: false
```

| YAML  | Environment variable            | Type    | Default |
| ----- | ------------------------------- | ------- | ------- |
| `dns` | `BEYLA_HOSTNAME_DNS_RESOLUTION` | boolean | `true`  |

If `true`, it will try to resolve the Beyla local hostname against the network DNS.
If `false`, it will use the local hostname.

| YAML                | Environment variable          | Type   | Default |
| ------------------- | ---------------- | ------ | ------- |
| `override_hostname` | `BEYLA_HOSTNAME` | string | (unset) |

If set, the host part of the Instance ID will use the provided string
instead of trying to automatically resolve the host name.

This option takes precedence over `dns`.

## Kubernetes decorator

If you run Beyla in a Kubernetes environment, you can configure it to decorate the traces
and metrics with the Standard OpenTelemetry labels:

- `k8s.namespace.name`
- `k8s.deployment.name`
- `k8s.statefulset.name`
- `k8s.replicaset.name`
- `k8s.daemonset.name`
- `k8s.node.name`
- `k8s.pod.name`
- `k8s.container.name`
- `k8s.pod.uid`
- `k8s.pod.start_time`
- `k8s.cluster.name`

In YAML, this section is named `kubernetes`, and is located under the
`attributes` top-level section. For example:

```yaml
attributes:
  kubernetes:
    enable: true
```

It is IMPORTANT to consider that enabling this feature requires a previous step of
providing some extra permissions to the Beyla Pod. Consult the
["Configuring Kubernetes metadata decoration section" in the "Running Beyla in Kubernetes"]({{< relref "../setup/kubernetes.md" >}}) page.

| YAML     | Environment variable         | Type    | Default |
| -------- | ---------------------------- | ------- | ------- |
| `enable` | `BEYLA_KUBE_METADATA_ENABLE` | boolean | `false` |

If set to `true`, Beyla will decorate the metrics and traces with Kubernetes metadata.

If set to `false`, the Kubernetes metadata decorator will be disabled.

If set to `autodetect`, Beyla will try to automatically detect if it is running inside
Kubernetes, and enable the metadata decoration if that is the case.

| YAML              | Environment variable      | Type   | Default          |
| ----------------- | ------------ | ------ | ---------------- |
| `kubeconfig_path` | `KUBECONFIG` | string | `~/.kube/config` |

This is a standard Kubernetes configuration environment variable, and is used
to tell Beyla where to find the Kubernetes configuration in order to try to
establish communication with the Kubernetes Cluster.

Usually you won't need to change this value.

| YAML                | Environment variable           | Type   | Default |
|---------------------|--------------------------------|--------|---------|
| `disable_informers` | `BEYLA_KUBE_DISABLE_INFORMERS` | string | (empty) |

The accepted value is a list that might contain `node` and `service`.

This option allows you to selectively disable some Kubernetes informers, which are continuously
listening to the Kubernetes API to obtain the metadata that is required for decorating
network metrics or application metrics and traces.

When Beyla is deployed as a DaemonSet in very large clusters, all the Beyla instances
creating multiple informers might end up overloading the Kubernetes API.

Disabling some informers would cause reported metadata to be incomplete, but
reduces the load of the Kubernetes API.

The Pods informer can't be disabled. For that purpose, you should disable the whole
Kubernetes metadata decoration.

| YAML                       | Environment variable                  | Type    | Default |
|----------------------------|---------------------------------------|---------|---------|
| `meta_restrict_local_node` | `BEYLA_KUBE_META_RESTRICT_LOCAL_NODE` | boolean | false   |

If true, Beyla stores Pod and Node metadata only from the node where the Beyla instance is running.

This option decreases the memory used to store the metadata, but some metrics
(such as network bytes or service graph metrics) would miss the metadata from destination
pods that are located in a different node.


| YAML                     | Environment variable                | Type     | Default |
|--------------------------|-------------------------------------|----------|---------|
| `informers_sync_timeout` | `BEYLA_KUBE_INFORMERS_SYNC_TIMEOUT` | Duration | 30s     |

Maximum time that Beyla waits for getting all the Kubernetes metadata before starting
to decorate metrics and traces. If this timeout is reached, Beyla starts normally but
the metadata attributes might be incomplete until all the Kubernetes metadata is locally
updated in background.

| YAML                      | Environment variable                 | Type     | Default |
|---------------------------|--------------------------------------|----------|---------|
| `informers_resync_period` | `BEYLA_KUBE_INFORMERS_RESYNC_PERIOD` | Duration | 30m     |

Beyla is subscribed to immediately receive any update on resources' metadata. In addition,
Beyla periodically resynchronizes the whole Kubernetes metadata at the frequency specified
by this property.

Higher values reduce the load on the Kubernetes API service.
