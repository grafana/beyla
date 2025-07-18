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

You can configure how Beyla decorates attributes for metrics and traces. Use the `attributes` top YAML section to enable and configure how attributes are set.

The [Beyla exported metrics](../../metrics/) document lists the attributes you can report with each metric. Beyla reports some attributes by default and hides others to control cardinality.

For each metric, you control which attributes to see with the `select` subsection. This is a map where each key is the name of a metric either in its OpenTelemetry or Prometheus port, and each metric has two sub-properties: `include` and `exclude`.

- `include` is a list of attributes to report. Each attribute can be a name or a wildcard, for example, `k8s.dst.*` to include all attributes starting with `k8s.dst`. If you don't provide an `include` list, Beyla reports the default attribute set, refer to [Beyla exported metrics](../../metrics/) for more information about default attributes for a given metric
- `exclude` is a list of attribute names or wildcards to remove from the `include` list, or the default attribute set

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

Additionally, you can use wildcards as metric names to add and exclude attributes for groups of metrics with the same name. For example:

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

In the previous example, all metrics with a name starting with `http_` or `http.` include all possible attributes except `http_path` and `http_route` or `http.path`/`http.route`. The `http_client_*` and `http_server_*` sections override the base configuration, enabling the `http_path` attribute for HTTP client metrics and `http_route` for HTTP server metrics.

When a metric name matches multiple definitions using wildcards, exact matches take precedence over wildcard matches.

## Distributed traces and context propagation

YAML section: `ebpf`

You can configure the component under the `ebpf` section of your YAML configuration or via environment variables.

| YAML<p>environment variable</p>                                           | Description                                                                                                                                                                      | Type    | Default  |
| ------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | -------- |
| `enable_context_propagation`<p>`BEYLA_BPF_ENABLE_CONTEXT_PROPAGATION`</p> | Deprecated. Use `context_propagation` instead. For more information, refer to the [enable context propagation section](#enable-context-propagation).                             | boolean | false    |
| `context_propagation`<p>`BEYLA_BPF_CONTEXT_PROPAGATION`</p>               | Controls trace context propagation method. Accepted: `all`, `headers`, `ip`, `disabled`. For more information, refer to the [context propagation section](#context-propagation). | string  | disabled |
| `track_request_headers`<p>`BEYLA_BPF_TRACK_REQUEST_HEADERS`</p>           | Track incoming `Traceparent` headers for trace spans. For more information, refer to the [track request headers section](#track-request-headers).                                | boolean | false    |

### Enable context propagation

Deprecated. Use `context_propagation` instead.

### Context propagation

Beyla injects the `Traceparent` header value for outgoing HTTP requests, so it can propagate any incoming context to downstream services. This context propagation works for any programming language.

For TLS encrypted HTTP requests (HTTPS), Beyla encodes the `Traceparent` header value at the TCP/IP packet level. Beyla must be present on both sides of the communication.

The TCP/IP packet level encoding uses Linux Traffic Control (TC). eBPF programs that also use TC must chain correctly with Beyla. For more information about chaining programs, see the [Cilium compatibility documentation](../../cilium-compatibility/).

You can disable the TCP/IP level encoding and TC programs by setting `context_propagation="headers"`. This context propagation is fully compatible with any OpenTelemetry distributed tracing library.

Context propagation values:

- `all`: Enable both HTTP and IP options context propagation
- `headers`: Enable context propagation via the HTTP headers only
- `ip`: Enable context propagation via the IP options field only
- `disabled`: Disable trace context propagation

To use this option in containerized environments (Kubernetes and Docker), you must:

- Deploy Beyla as a `DaemonSet` with host network access `hostNetwork: true`
- Volume mount the `/sys/fs/cgroup` path from the host as local `/sys/fs/cgroup` path
- Grant the `CAP_NET_ADMIN` capability to the Beyla container

gRPC and HTTP2 are not supported.

For an example of how to configure distributed traces in Kubernetes, see our [Distributed traces with Beyla](../../distributed-traces/) guide.

### Track request headers

This option lets Beyla process any incoming `Traceparent` header values. If enabled, when Beyla sees an incoming server request with a `Traceparent` header value, it uses the provided 'trace id' to create its own trace spans.

This option does not affect Go applications, where the `Traceparent` field is always processed.

Enabling this option may increase performance overhead in high request volume scenarios. This option is only useful when generating Beyla traces; it does not affect metrics.

### Other attributes

| YAML option<p>Environment variable</p>                    | Description                                                   | Type    | Default |
| --------------------------------------------------------- | ------------------------------------------------------------- | ------- | ------- |
| `heuristic_sql_detect`<p>`BEYLA_HEURISTIC_SQL_DETECT`</p> | Enable heuristic SQL client detection. See below for details. | boolean | (false) |

The `heuristic sql detect` option lets Beyla detect SQL client requests by inspecting query statements, even if the protocol is not directly supported. By default, Beyla detects SQL client requests by their binary protocol format. If you use a database technology not directly supported by Beyla, you can enable this option to get database client telemetry. This option is not enabled by default, because it can create false positives, for example, if an application sends SQL text for logging through a TCP connection. Currently, Beyla natively supports the Postgres and MySQL binary protocols.

## Instance ID decoration

YAML section: `attributes.instance_id`

Beyla decorates metrics and traces with a unique instance ID string, identifying each instrumented application. By default, Beyla uses the host name that runs Beyla (can be a container or Pod name), followed by the PID of the instrumented process. You can override how the instance ID is composed in the `instance_id` YAML subsection under the `attributes` top-level section.

For example:

```yaml
attributes:
  instance_id:
    dns: false
```

| YAML<p>environment variable</p>             | Description                                                                                                                                                                               | Type    | Default |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------- |
| `dns`<p>`BEYLA_HOSTNAME_DNS_RESOLUTION`</p> | If `true`, Beyla tries to resolve the local hostname against the network DNS. If `false`, uses local name. For more information, refer to the [dns section](#dns).                        | boolean | true    |
| `override_hostname`<p>`BEYLA_HOSTNAME`</p>  | If set, Beyla uses the provided string as the host part of the Instance ID. Overrides DNS resolution. For more information, refer to the [override hostname section](#override-hostname). | string  | (unset) |

### DNS

If `true`, Beyla tries to resolve the local hostname against the network DNS. If `false`, it uses the local hostname.

### Override hostname

If set, Beyla uses the provided string as the host part of the Instance ID instead of trying to resolve the host name. This option takes precedence over `dns`.

## Kubernetes decorator

YAML section: `attributes.kubernetes`

You can configure the component under the `attributes.kubernetes` section of your YAML configuration or via environment variables.

To enable this feature, you must provide extra permissions to the Beyla Pod. See the ["Configuring Kubernetes metadata decoration section" in the "Running Beyla in Kubernetes"](../../setup/kubernetes/) page.

If you set this option to `true`, Beyla decorates metrics and traces with Kubernetes metadata. If you set it to `false`, Beyla disables the Kubernetes metadata decorator. If you set it to `autodetect`, Beyla tries to detect if it is running inside Kubernetes and enables metadata decoration if so.

For example:

```yaml
attributes:
  kubernetes:
    enable: true
```

| YAML<p>environment variable</p>                                        | Description                                                                                                                                                                                   | Type           | Default        |
| ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------- | -------------- |
| `enable`<p>`BEYLA_KUBE_METADATA_ENABLE`</p>                            | Enable or disable Kubernetes metadata decoration. Set to `autodetect` to enable if running in Kubernetes. For more information, refer to the [enable kubernetes section](#enable-kubernetes). | boolean/string | false          |
| `kubeconfig_path`<p>`KUBECONFIG`</p>                                   | Path to the Kubernetes configuration file. For more information, refer to the [Kubernetes configuration path section](#kubernete-configuration-path).                                         | string         | ~/.kube/config |
| `disable_informers`<p>`BEYLA_KUBE_DISABLE_INFORMERS`</p>               | List of informers to disable (`node`, `service`). For more information, refer to the [disable informers section](#disable-informers).                                                         | string         | (empty)        |
| `meta_restrict_local_node`<p>`BEYLA_KUBE_META_RESTRICT_LOCAL_NODE`</p> | Restrict metadata to local node only. For more information, refer to the [meta restrict local node section](#meta-restrict-local-node).                                                       | boolean        | false          |
| `informers_sync_timeout`<p>`BEYLA_KUBE_INFORMERS_SYNC_TIMEOUT`</p>     | Maximum time to wait for Kubernetes metadata before starting. For more information, refer to the [informers sync timeout section](#informers-sync-timeout).                                   | Duration       | 30s            |
| `informers_resync_period`<p>`BEYLA_KUBE_INFORMERS_RESYNC_PERIOD`</p>   | Periodically resynchronize all Kubernetes metadata. For more information, refer to the [informers resynchronization period section](#informers-resynchronization-period).                     | Duration       | 30m            |
| `service_name_template`<p>`BEYLA_SERVICE_NAME_TEMPLATE`</p>            | Go template for service names. For more information, refer to the [service name template section](#service-name-template).                                                                    | string         | (empty)        |

### Enable kubernetes

If you run Beyla in a Kubernetes environment, you can configure it to decorate traces and metrics with the standard OpenTelemetry labels:

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

### Kubernetes configuration path

This is a standard Kubernetes configuration environment variable. Use it to tell Beyla where to find the Kubernetes configuration to communicate with the Kubernetes Cluster. Usually, you do not need to change this value.

### Disable informers

The accepted value is a list that might contain `node` and `service`.

This option lets you selectively disable some Kubernetes informers, which continuously listen to the Kubernetes API to get the metadata needed for decorating network metrics or application metrics and traces.

When you deploy Beyla as a DaemonSet in very large clusters, all the Beyla instances creating multiple informers might overload the Kubernetes API.

Disabling some informers causes reported metadata to be incomplete, but reduces the load on the Kubernetes API.

You cannot disable the Pods informer. To do that, disable the whole Kubernetes metadata decoration.

### Meta restrict local node

If true, Beyla stores Pod and Node metadata only from the node where the Beyla instance runs.

This option decreases the memory used to store metadata, but some metrics such as network bytes or service graph metrics won't include metadata from destination pods on a different node.

### Informers sync timeout

This is the maximum time Beyla waits to get all the Kubernetes metadata before starting to decorate metrics and traces. If this timeout is reached, Beyla starts normally, but the metadata attributes might be incomplete until all the Kubernetes metadata is updated in the background.

### Informers resynchronization period

Beyla immediately receives any update on resources' metadata. In addition, Beyla periodically resynchronizes all Kubernetes metadata at the frequency you specify with this property. Higher values reduce the load on the Kubernetes API service.

### Service name template

You can template service names using Go templates. This lets you create conditional or extended service names.

The following context is available to the template:

```
Meta: (*informer.ObjectMeta)
  Name: (string)
  Namespace: (string)
  Labels:
    label1: lv1
    label2: lv2
  Annotations:
    Anno1: av1
    Anno2: av2
  Pod: (*PodInfo)
  ...

ContainerName: (string)
```

You can find the full object and structure in the `kubecache informer.pb.go` source file.

Service name template examples:

```
{{- .Meta.Namespace }}/{{ index .Meta.Labels "app.kubernetes.io/name" }}/{{ index .Meta.Labels "app.kubernetes.io/component" -}}{{ if .ContainerName }}/{{ .ContainerName -}}{{ end -}}
```

or

```
{{- .Meta.Namespace }}/{{ index .Meta.Labels "app.kubernetes.io/name" }}/{{ index .Meta.Labels "app.kubernetes.io/component" -}}
```

In this example, only the first line is used and trimmed to prevent white space in the service name.

## Extra group attributes

Beyla allows you to enhance your metrics with custom attributes using the `extra_group_attributes` configuration. This gives you the flexibility to include additional metadata in your metrics, beyond the standard set.

To use this feature, specify the group name and the list of attributes you want to include in that group.

Currently, only the `k8s_app_meta` group is supported. This group contains Kubernetes-specific metadata such as Pod name, namespace, container name, Pod UID, and more.

Example configuration:

```yaml
attributes:
  kubernetes:
    enable: true
  extra_group_attributes:
    k8s_app_meta: ["k8s.app.version"]
```

In this example:

- Adding `k8s.app.version` to the `resource_labels` block causes the `k8s.app.version` label to appear in the metrics.
- You can also define annotations with the prefix `resource.opentelemetry.io/` and suffix `k8s.app.version` in your Kubernetes manifests, these annotations are automatically included in the metrics.

The following table describes the default group attributes.

| Group          | Label                  |
| -------------- | ---------------------- |
| `k8s_app_meta` | `k8s.namespace.name`   |
| `k8s_app_meta` | `k8s.pod.name`         |
| `k8s_app_meta` | `k8s.container.name`   |
| `k8s_app_meta` | `k8s.deployment.name`  |
| `k8s_app_meta` | `k8s.replicaset.name`  |
| `k8s_app_meta` | `k8s.daemonset.name`   |
| `k8s_app_meta` | `k8s.statefulset.name` |
| `k8s_app_meta` | `k8s.node.name`        |
| `k8s_app_meta` | `k8s.pod.uid`          |
| `k8s_app_meta` | `k8s.pod.start_time`   |
| `k8s_app_meta` | `k8s.cluster.name`     |
| `k8s_app_meta` | `k8s.owner.name`       |

And the following table describes the metrics and their associated groups.
| Group | OTEL Metric | Prom Metric |
|---------------------|---------------------------------|---------------------------------|
| `k8s_app_meta` | `process.cpu.utilization` | `process_cpu_utilization_ratio` |
| `k8s_app_meta` | `process.cpu.time` | `process_cpu_time_seconds_total` |
| `k8s_app_meta` | `process.memory.usage` | `process_memory_usage_bytes` |
| `k8s_app_meta` | `process.memory.virtual` | `process_memory_virtual_bytes` |
| `k8s_app_meta` | `process.disk.io` | `process_disk_io_bytes_total` |
| `k8s_app_meta` | `messaging.publish.duration` | `messaging_publish_duration_seconds` |
| `k8s_app_meta` | `messaging.process.duration` | `messaging_process_duration_seconds` |
| `k8s_app_meta` | `http.server.request.duration` | `http_server_request_duration_seconds` |
| `k8s_app_meta` | `http.server.request.body.size` | `http_server_request_body_size_bytes` |
| `k8s_app_meta` | `http.server.response.body.size` | `http_server_response_body_size_bytes` |
| `k8s_app_meta` | `http.client.request.duration` | `http_client_request_duration_seconds` |
| `k8s_app_meta` | `http.client.request.body.size` | `http_client_request_body_size_bytes` |
| `k8s_app_meta` | `http.client.response.body.size` | `http_client_response_body_size_bytes` |
| `k8s_app_meta` | `rpc.client.duration` | `rpc_client_duration_seconds` |
| `k8s_app_meta` | `rpc.server.duration` | `rpc_server_duration_seconds` |
| `k8s_app_meta` | `db.client.operation.duration` | `db_client_operation_duration_seconds` |
| `k8s_app_meta` | `gpu.kernel.launch.calls` | `gpu_kernel_launch_calls_total` |
| `k8s_app_meta` | `gpu.kernel.grid.size` | `gpu_kernel_grid_size_total` |
| `k8s_app_meta` | `gpu.kernel.block.size` | `gpu_kernel_block_size_total` |
| `k8s_app_meta` | `gpu.memory.allocations` | `gpu_memory_allocations_bytes_total` |
