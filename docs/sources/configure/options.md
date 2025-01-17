---
title: Beyla global configuration properties
menuTitle: Global properties
description: Configure global configuration properties that apply to Beyla core.
weight: 2
keywords:
  - Beyla
  - eBPF
aliases:
  - /docs/grafana-cloud/monitor-applications/beyla/configure/options/
---

# Beyla global configuration properties

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

Refer to the [example YAML configuration file](../example/) for configuration file template.

Currently, Beyla consist of a pipeline of components which
generate, transform, and export traces from HTTP and GRPC applications. In the
YAML configuration, each component has its own first-level section.

Optionally, Beyla also provides network-level metrics, which are documented in the
[Network metrics section of the Beyla documentation](../../network/).

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
