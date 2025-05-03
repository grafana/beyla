---
title: Configure Beyla service discovery
menuTitle: Service discovery
description: Configure how the Beyla service discovery component searches for processes to instrument.
weight: 20
keywords:
  - Beyla
  - eBPF
---

# Configure Beyla service discovery

The `executable_name`, `open_port`, `service_name` and `service_namespace` are top-level
properties that simplify the configuration of Beyla to instrument a single service, or
a group of related services.

In some scenarios, Beyla will instrument a big variety of services; for example,
as a [Kubernetes DaemonSet](../../setup/kubernetes/) that instruments all
the services in a node. The `discovery` YAML section will let you specify a higher
differentiation degree in the services that Beyla can instrument.

For example, it will allow overriding the service name and namespace per service type.

| YAML       | Environment variable | Type            | Default |
| ---------- | -------------------- | --------------- | ------- |
| `services` | N/A                  | list of objects | (unset) |

This section allows specifying different selection criteria for different services,
as well as overriding some of their metadata, such as their reported name or
namespace.

For more details about this section, go to the [discovery services section](#discovery-services-section)
of this document.

| YAML               | Environment variable | Type            | Default |
| ------------------ | -------------------- | --------------- | ------- |
| `exclude_services` | N/A                  | list of objects | (unset) |

This section allows for specifying selection criteria for excluding services from
being instrumented. It follows the same definition format as described in the
[discovery services section](#discovery-services-section) of this document.

This option is useful for avoiding instrumentation of services which are typically
found in observability environments. For example, use this option to exclude instrumenting
Prometheus.

| YAML                       | Environment variable  | Type              | Default                                           |
| -------------------------- | --------------------- | ----------------- | ------------------------------------------------- |
| `default_exclude_services` | N/A                   | list of objects   | Path: `(?:^\|\/)(beyla$\|alloy$\|otelcol[^\/]*$)` |

Disables instrumentation of Beyla itself (self-instrumentation), as well as Grafana Alloy and the
OpenTelemetry Collector. Set to empty to allow Beyla to instrument itself as well as these other components.
Note: to enable such self-instrumentation, it is still required to include them in the `services` section.

| YAML                       | Environment variable             | Type    | Default |
| -------------------------- | -------------------------------- | ------- | ------- |
| `skip_go_specific_tracers` | `BEYLA_SKIP_GO_SPECIFIC_TRACERS` | boolean | false   |

Disables the detection of Go specifics when the **ebpf** tracer inspects executables to be instrumented.
The tracer will fallback to using generic instrumentation, which will generally be less efficient.

| YAML                                 | Environment variable                       | Type    | Default |
| ------------------------------------ | ------------------------------------------ | ------- | ------- |
| `exclude_otel_instrumented_services` | `BEYLA_EXCLUDE_OTEL_INSTRUMENTED_SERVICES` | boolean | true    |

Disables Beyla instrumentation of services which are already instrumented with OpenTelemetry. Since Beyla
is often deployed to monitor all services in a Kubernetes cluster, monitoring already instrumented services
can lead to duplicate telemetry data, unless the instrumentation selection (or exclusion) criteria is
carefully crafted. To avoid unnecessary configuration overhead, Beyla monitors for the OpenTelemetry SDK calls
to publish metrics and traces, and automatically turns off instrumentation of services which publish their own
telemetry data. Turn this option off if your application generated telemetry data doesn't conflict with the
Beyla generated metrics and traces.

### Discovery services section

Example of YAML file allowing the selection of multiple groups of services:

```yaml
discovery:
  services:
    - exe_path: (worker)|(backend)|(frontend)
      namespace: MyApplication
    - exe_path: loadgen
      namespace: testing
      name: "TestLoadGenerator"
```

The above example YAML will select two groups of executables. The first group will be formed by any
process whose executable path contains the `worker`, `backend` or `frontend` text. For each
service, Beyla will take the service name attribute from the executable name. The reported
service namespace for all the processes matching this group will be `MyApplication`.

The second group in the above example YAML will select any executable whose path contains
`regexp`, but instead of taking the service name from the executable name, it will override
the service name with `TestLoadGenerator`.

The rest of this section describes the properties that are accepted in each entry of the
`services` list.

Each `services` entry is a map where the properties can be grouped according to two purposes:

- Overriding the reported service name and namespace: `name` and `namespace` properties.
- Selecting the process to instrument: the rest of the properties, referred as _selectors_ in
  this documentation.

| YAML   | Environment variable | Type   | Default           |
| ------ | ------- | ------ | ----------------- |
| `name` | --      | string | (see description) |

**Deprecated**

Defines a name for the matching instrumented service. It will be used to populate the `service.name`
OTEL property and the `service_name` Prometheus property in the exported metrics/traces.

This option is deprecated, as multiple matches for the same `services` entry would involve
multiple services sharing the same name.
Refer to the [override service name and namespace](#override-service-name-and-namespace) section
to enable automatic configuration of service name and namespace from diverse metadata sources.

If the property is not set, it will default to any of the following properties, in order of
precedence:

- If Kubernetes is enabled:
  1. The name of the Deployment that runs the instrumented process, if any.
  2. The name of the ReplicaSet/DaemonSet/StatefulSet that runs the instrumented process, if any.
  3. The name of the Pod that runs the instrumented process.
- If Kubernetes is not enabled:
  1. The name of the process executable file.

If multiple processes match the service selection criteria described below,
the metrics and traces for all the instances might share the same service name;
for example, when multiple instrumented processes run under the same Deployment,
or have the same executable name. In that case, the reported `instance` attribute
would allow differentiating the different instances
of the service.

| YAML        | Environment variable | Type   | Default                  |
| ----------- | ------- | ------ | ------------------------ |
| `namespace` | --      | string | (empty or K8s namespace) |

**Deprecated**.

Defines a namespace for the matching instrumented service.
If the property is not set, it will be defaulted to the Kubernetes namespace of
that runs the instrumented process, if Kubernetes is available, or empty when
Kubernetes is not available.

This option is deprecated. Refer to the [overriding service name and namespace](#override-service-name-and-namespace) section
to enable automatic configuration of service name and namespace from diverse metadata sources.

It is important to notice that this namespace is not a selector for Kubernetes namespaces. Its
value will be use to set the value of standard telemetry attributes. For example, the
[OpenTelemetry `service.namespace` attribute](https://opentelemetry.io/docs/specs/otel/common/attribute-naming/).

| YAML         | Environment variable | Type   | Default |
| ------------ | ------- | ------ | ------- |
| `open_ports` | --      | string | (unset) |

Selects the process to instrument by the port it has open (listens to). This property
accepts a comma-separated list of ports (for example, `80`), and port ranges (for example, `8000-8999`).
If the executable matching only one of the ports in the list, it is considered to match
the selection criteria.

For example, specifying the following property:

```
open_port: 80,443,8000-8999
```

Would make Beyla to select any executable that opens port 80, 443, or any of the ports between 8000 and 8999 included.

If other selectors are specified in the same `services` entry, the processes to be
selected need to match all the selector properties.

If an executable opens multiple ports, only one of the ports needs to be specified
for Beyla **to instrument all the
HTTP/S and GRPC requests on all application ports**. At the moment, there is no way to
restrict the instrumentation only to the methods exposed through a specific port.

| YAML       | Environment variable | Type                        | Default |
| ---------- | ------- | --------------------------- | ------- |
| `exe_path` | --      | string (regular expression) | (unset) |

Selects the processes to instrument by their executable name path. This property accepts
a regular expression to be matched against the full executable command line, including the directory
where the executable resides on the file system.

Beyla will try to instrument all the processes with an executable path matching this property.
For example, setting `exe_path: .*` will make Beyla to try to instrument all the
executables in the host.

If other selectors are specified in the same `services` entry, the processes to be
selected need to match all the selector properties.

| YAML              | Environment variable | Type    | Default |
| ----------------- | -------------------- | --------| ------- |
| `containers_only` | --                   | boolean |  false  |

Selects processes to instrument which are running in an OCI container.
To perform this check, Beyla inspects the process network namespace and 
matches it against its own network namespace. This option is ignored, if 
there are insufficient permissions given to the Beyla process to perform 
the network namespace inspection.

If other selectors are specified in the same `services` entry, the processes to be
selected need to match all the selector properties.

| YAML            | Environment variable | Type                        | Default |
| --------------- | ------- | --------------------------- | ------- |
| `k8s_namespace` | --      | string (regular expression) | (unset) |

This selector property will limit the instrumentation to the applications
running in the Kubernetes Namespaces with a name matching the provided regular
expression.

If other selectors are specified in the same `services` entry, the processes to be
selected need to match all the selector properties.

| YAML           | Environment variable | Type                        | Default |
| -------------- | ------- | --------------------------- | ------- |
| `k8s_pod_name` | --      | string (regular expression) | (unset) |

This selector property will limit the instrumentation to the applications
running in the Kubernetes Pods with a name matching the provided regular
expression.

If other selectors are specified in the same `services` entry, the processes to be
selected need to match all the selector properties.

| YAML                  | Environment variable | Type                        | Default |
| --------------------- | ------- | --------------------------- | ------- |
| `k8s_deployment_name` | --      | string (regular expression) | (unset) |

This selector property will limit the instrumentation to the applications
running in the Kubernetes Deployments with a name matching the provided regular
expression.

If other selectors are specified in the same `services` entry, the processes to be
selected need to match all the selector properties.

| YAML                  | Environment variable | Type                        | Default |
| --------------------- | ------- | --------------------------- | ------- |
| `k8s_replicaset_name` | --      | string (regular expression) | (unset) |

This selector property will limit the instrumentation to the applications
running in the Kubernetes ReplicaSets with a name matching the provided regular
expression.

If other selectors are specified in the same `services` entry, the processes to be
selected need to match all the selector properties.

| YAML                   | Environment variable | Type                        | Default |
| ---------------------- | ------- | --------------------------- | ------- |
| `k8s_statefulset_name` | --      | string (regular expression) | (unset) |

This selector property will limit the instrumentation to the applications
running in the Kubernetes StatefulSets with a name matching the provided regular
expression.

If other selectors are specified in the same `services` entry, the processes to be
selected need to match all the selector properties.

| YAML                 | Environment variable | Type                        | Default |
| -------------------- | ------- | --------------------------- | ------- |
| `k8s_daemonset_name` | --      | string (regular expression) | (unset) |

This selector property will limit the instrumentation to the applications
running in the Kubernetes DaemonSet with a name matching the provided regular
expression.

If other selectors are specified in the same `services` entry, the processes to be
selected need to match all the selector properties.

| YAML             | Environment variable | Type                        | Default |
| ---------------- | ------- | --------------------------- | ------- |
| `k8s_owner_name` | --      | string (regular expression) | (unset) |

This selector property will limit the instrumentation to the applications
running in the Pods having owned by either a `Deployment`, `ReplicaSet`,
`DaemonSet` or `StatefulSet` with a name matching the provided regular
expression.

If other selectors are specified in the same `services` entry, the processes to be
selected need to match all the selector properties.

| YAML             | Environment variable | Type                        | Default |
| ---------------- | ------- | --------------------------- | ------- |
| `k8s_pod_labels` | --      | map\[string\]string (regular expression) | (unset) |

This selector property limits the instrumentation to the applications
running in the Pods having labels with keys matching the provided value as regular expression.

If other selectors are specified in the same `services` entry, the processes to be
selected need to match all the selector properties.

For example:

```yaml
discovery:
  services:
    - k8s_namespace: frontend
      k8s_pod_labels:
        instrument: beyla
```

The preceding example discovers all Pods in the `frontend` namespace that have a label
`instrument` with a value that matches the regular expression `beyla`.

| YAML                  | Environment variable | Type                                     | Default |
|-----------------------|----------------------|------------------------------------------|---------|
| `k8s_pod_annotations` | --                   | map\[string\]string (regular expression) | (unset) |

This selector property limits the instrumentation to the applications
running in the Pods having annotations with keys matching the provided value as regular expression.

If other selectors are specified in the same `services` entry, the processes to be
selected need to match all the selector properties.

For example:

```yaml
discovery:
  services:
    - k8s_namespace: backend
      k8s_pod_annotations:
        beyla.instrument: "true"
```

The preceding example discovers all Pods in the `backend` namespace that have an annotation
`beyla.instrument` with a value that matches the regular expression `true`.

## Override service name and namespace

If the instrumentation data is exported via OpenTelemetry or via Prometheus, Beyla follows the
[service name conventions from the OpenTelemetry operator](https://github.com/open-telemetry/opentelemetry-operator/blob/main/README.md#how-resource-attributes-are-calculated-from-the-pods-metadata)
to improve the interoperability of Beyla with other instrumentation solutions.

Beyla uses the following criteria in this order to automatically set the service name and namespace is:

1. Resource attributes set via `OTEL_RESOURCE_ATTRIBUTES` and `OTEL_SERVICE_NAME` environment variables of the
   instrumented process or container.
2. In Kubernetes, resource attributes set via the following Pod annotations:
    - `resource.opentelemetry.io/service.name`
    - `resource.opentelemetry.io/service.namespace`
3. In Kubernetes, resource attributes set via the following Pod labels:
    - `app.kubernetes.io/name` sets the service name
    - `app.kubernetes.io/part-of` sets the service namespace
4. In Kubernetes, resource attributes calculated from the Pod owner's metadata, in the following order (according to
   their availability):
    - `k8s.deployment.name`
    - `k8s.replicaset.name`
    - `k8s.statefulset.name`
    - `k8s.daemonset.name`
    - `k8s.cronjob.name`
    - `k8s.job.name`
    - `k8s.pod.name`
    - `k8s.container.name`
5. The executable name of the instrumented process.

The Kubernetes labels from the previous bullet 3 can be overridden via configuration.

In YAML:
```yaml
kubernetes:
  resource_labels:
    service.name:
      # gets service name from the first existing Pod label
      - override-svc-name
      - app.kubernetes.io/name
    service.namespace:
      # gets service namespace from the first existing Pod label
      - override-svc-ns
      - app.kubernetes.io/part-of
```

They accept a comma-separated list of annotation and label names.
