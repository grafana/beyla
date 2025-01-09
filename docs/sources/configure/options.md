---
title: Beyla configuration options
menuTitle: Options
description: Learn about the configuration options available for Beyla.
weight: 1
keywords:
  - Beyla
  - eBPF
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/configure/options/
---

# Beyla configuration options

Beyla can be configured via environment variables or via
a YAML configuration file that is passed either with the `-config` command-line
argument or the `BEYLA_CONFIG_PATH` environment variable.
Environment variables have priority over the properties in the
configuration file. For example, in the following command line, the `BEYLA_OPEN_PORT` option,
is used to override any `open_port` settings inside the config.yaml file:

```
$ BEYLA_OPEN_PORT=8080 beyla -config /path/to/config.yaml
```

or

```
$ BEYLA_OPEN_PORT=8080 BEYLA_CONFIG_PATH=/path/to/config.yaml beyla
```

At the end of this document, there is an [example of YAML configuration file](#yaml-file-example).

Currently, Beyla consist of a pipeline of components which
generate, transform, and export traces from HTTP and GRPC applications. In the
YAML configuration, each component has its own first-level section.

Optionally, Beyla also provides network-level metrics, which are documented in the
[Network metrics section of the Beyla documentation]({{< relref "../network" >}}).

A quick description of the components:

- [Service discovery](#service-discovery) searches for instrumentable processes matching
  a given criteria.
- [EBPF tracer](#ebpf-tracer) instruments the HTTP and GRPC services of an external process,
  creates service traces and forwards them to the next stage of the pipeline.
- [Configuration of metrics and traces attributes](#configuration-of-metrics-and-traces-attributes) to control
  which attributes are reported.
- [Routes decorator](#routes-decorator) will match HTTP paths (e.g. `/user/1234/info`)
  into user-provided HTTP routes (e.g. `/user/{id}/info`). If no routes are defined,
  the incoming data will be directly forwarded to the next stage.
- [Kubernetes decorator](#kubernetes-decorator) will decorate the metrics and traces
  with Kubernetes metadata of the instrumented Pods.
- [Filter metrics and traces by attribute values](#filter-metrics-and-traces-by-attribute-values).
- [Grafana Cloud OTEL exporter for metrics and traces](#using-the-grafana-cloud-otel-endpoint-to-ingest-metrics-and-traces)
  simplifies the submission of OpenTelemetry metrics and traces to Grafana cloud.
- [OTEL metrics exporter](#otel-metrics-exporter) exports metrics data to an external
  [OpenTelemetry](https://opentelemetry.io/) metrics collector.
- [OTEL traces exporter](#otel-traces-exporter) exports span data to an external
  [OpenTelemetry](https://opentelemetry.io/) traces collector.
- [Prometheus HTTP endpoint](#prometheus-http-endpoint) enables an HTTP endpoint
  that allows any external scraper to pull metrics in [Prometheus](https://prometheus.io/) format.
- [Internal metrics reporter](#internal-metrics-reporter) optionally reports metrics about the internal behavior of
  the auto-instrumentation tool in [Prometheus](https://prometheus.io/) format.

The following sections explain the global configuration properties, as well as
the options for each component.

## Global configuration properties

The properties in this section are first-level YAML properties, as they apply to the
whole Beyla configuration:

| YAML              | Environment variable                 | Type   | Default |
| ----------------- | ----------------------- | ------ | ------- |
| `executable_name` | `BEYLA_EXECUTABLE_NAME` | string | (unset) |

Selects the process to instrument by the executable name path. This property accepts
a regular expression to be matched against the full executable command line, including the directory
where the executable resides on the file system.

This property is used to select a single process to instrument, or a group of processes of
similar characteristics. For more fine-grained process selection and grouping, you can
follow the instructions in the [service discovery section](#service-discovery).

If the `open_port` property is set, the executable to be selected needs to match both properties.

When instrumenting by using the executable name, choose a non-ambiguous name, a name that
will match a single executable on the target system.
For example, if you set `BEYLA_EXECUTABLE_NAME=server`, and you have running two processes whose executables
have the following paths:

```sh
/usr/local/bin/language-server
/opt/app/server
```

Beyla will match indistinctly one of the above processes and instrument both.
If you just want to instrument one of them, you should be as concrete as possible about
the value of the setting. For example, `BEYLA_EXECUTABLE_NAME=/opt/app/server`
or just `BEYLA_EXECUTABLE_NAME=/server`.

| YAML        | Environment variable           | Type   | Default |
| ----------- | ----------------- | ------ | ------- |
| `open_port` | `BEYLA_OPEN_PORT` | string | (unset) |

Selects the process to instrument by the port it has open (listens to). This property
accepts a comma-separated list of ports (for example, `80`), and port ranges (for example, `8000-8999`).
If the executable matching only one of the ports in the list, it is considered to match
the selection criteria.

For example, specifying the following property:

```
open_port: 80,443,8000-8999
```

Would make Beyla to select any executable that opens port 80, 443, or any of the ports between 8000 and 8999 included.

This property is used to select a single process to instrument, or a group of processes of
similar characteristics. For more fine-grained process selection and grouping, you can
follow the instructions in the [service discovery section](#service-discovery).

If the `executable_name` property is set, the executable to be selected needs to match both properties.

If an executable opens multiple ports, only one of the ports needs to be specified
for Beyla **to instrument all the
HTTP/S and GRPC requests on all application ports**. At the moment, there is no way to
restrict the instrumentation only to the methods exposed through a specific port.

If the specified port range is wide (e.g. `1-65535`) Beyla will try to execute all the processes
owning one of the ports in the range.

| YAML           | Environment variable                                     | Type   | Default                                               |
| -------------- | ------------------------------------------- | ------ | ----------------------------------------------------- |
| `service_name` | `BEYLA_SERVICE_NAME` or `OTEL_SERVICE_NAME` | string | (see [service discovery](#service-discovery) section) |

Overrides the name of the instrumented service to be reported by the metrics exporter.
Defining this property is equivalent to add a `name` entry into the [`discovery.services` YAML
section](#service-discovery).

If a single instance of Beyla is instrumenting multiple instances of different processes,
they will share the same service name even if they are different. If you need that a
single instance of Beyla report different service names, follow the instructions in the
[service discovery section](#service-discovery).

| YAML                | Environment variable                   | Type   | Default                                               |
| ------------------- | ------------------------- | ------ | ----------------------------------------------------- |
| `service_namespace` | `BEYLA_SERVICE_NAMESPACE` | string | (see [service discovery](#service-discovery) section) |

Optionally, allows assigning a namespace for the service selected from the `executable_name`
or `open_port` properties.

Defining this property is equivalent to add a `name` entry into the [`discovery.services` YAML
section](#service-discovery).

This will assume a single namespace for all the services instrumented
by Beyla. If you need that a single instance of Beyla groups multiple services
into different namespaces, follow the instructions in the
[service discovery section](#service-discovery).

It is important to notice that this namespace is not a selector for Kubernetes namespaces. Its
value will be use to set the value of standard telemetry attributes. For example, the
[OpenTelemetry `service.namespace` attribute](https://opentelemetry.io/docs/specs/otel/common/attribute-naming/).

| YAML        | Environment variable           | Type   | Default |
| ----------- | ----------------- | ------ | ------- |
| `log_level` | `BEYLA_LOG_LEVEL` | string | `INFO`  |

Sets the verbosity level of the process standard output logger.
Valid log level values are: `DEBUG`, `INFO`, `WARN` and `ERROR`.
`DEBUG` being the most verbose and `ERROR` the least verbose.

| YAML            | Environment variable  | Type    | Default    |
| --------------  | --------------------- | ------- | ---------- |
| `trace_printer` | `BEYLA_TRACE_PRINTER` | string  | `disabled` |

<a id="printer"></a>

Prints any instrumented trace on the standard output. The value of
this option specify the format to be used when printing the trace. Valid
formats are:

| Value         | Description                    |
|---------------|--------------------------------|
| `disabled`    | disables the printer           |
| `text`        | prints a concise line of text  |
| `json`        | prints a compact JSON object   |
| `json_indent` | prints an indented JSON object |

| YAML               | Environment variable     | Type     | Default    |
| -----------------  | ------------------------ | -------- | ---------- |
| `enforce_sys_caps` | `BEYLA_ENFORCE_SYS_CAPS` | boolean  | `true`     |

<a id="caps"></a>

If you have set the `enforce_sys_caps` to true, if the required system
capabilities are not present Beyla aborts its startup and logs a list of the
missing capabilities.

If you have set the configuration option to `false`, Beyla logs a list of the
missing capabilities only.

## Configuration of metrics and traces attributes

Grafana Beyla allows configuring how some attributes for metrics and traces
are decorated. Under the `attributes` top YAML sections, you can enable
other subsections configure how some attributes are set.

### Instance ID decoration

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

### Kubernetes decorator

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
