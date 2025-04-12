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

<!-- vale Grafana.Paragraphs = NO -->

# Beyla global configuration properties

Beyla can be configured via environment variables or via a YAML configuration file passed either with the `-config` command-line argument or the `BEYLA_CONFIG_PATH` environment variable.
Environment variables have priority over the properties in the configuration file.
For example, in the following command line, the `BEYLA_OPEN_PORT` option overrides any `open_port` settings inside config.yaml:

**Config argument:**

```sh
BEYLA_OPEN_PORT=8080 beyla -config /path/to/config.yaml
```

**Config environment variable:**

```sh
BEYLA_OPEN_PORT=8080 BEYLA_CONFIG_PATH=/path/to/config.yaml beyla
```

Refer to the [example YAML configuration file](../example/) for a configuration file template.

Beyla consists of a pipeline of components that generate, transform, and export traces from HTTP and GRPC applications.
In the YAML configuration, each component has its own first-level section.

Optionally, Beyla also provides network-level metrics, refer to the [network metrics documentation](../../network/) for more information.

The following sections explain the global configuration properties that apply to the entire Beyla configuration:

| Lowercase YAML option<br>Uppercase environment variable option | Description                                                                                                           | Type    | Default               |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------- | --------------------- |
| `executable_name`<br>`BEYLA_EXECUTABLE_NAME`                   | Selects the process to instrument by regular expression matching against the full executable path.                    | string  | unset                 |
| `open_port`<br>`BEYLA_OPEN_PORT`                               | Selects a process to instrument by open ports. Accepts comma-separated lists of ports and port ranges.                | string  | unset                 |
| `shutdown_timeout`<br>`BEYLA_SHUTDOWN_TIMEOUT`                               | Sets the timeout for a graceful shutdown                | string  | "5m"                 |
| `service_name`<br>`BEYLA_SERVICE_NAME`                         | **Deprecated** Overrides the name of the instrumented service for metrics export.                                     | string  | see service discovery |
| `service_namespace`<br>`BEYLA_SERVICE_NAMESPACE`               | **Deprecated** Assigns a namespace for the selected service.                                                          | string  | see service discovery |
| `log_level`<br>`BEYLA_LOG_LEVEL`                               | Sets process logger verbosity. Valid values: `DEBUG`, `INFO`, `WARN`, `ERROR`.                                        | string  | `INFO`                |
| `trace_printer`<br>`BEYLA_TRACE_PRINTER`                       | Prints instrumented traces to stdout in a specified format, refer to [trace printer formats](#trace-printer-formats). | string  | `disabled`            |
| `enforce_sys_caps`<br>`BEYLA_ENFORCE_SYS_CAPS`                 | Controls how Beyla handles missing system capabilities at startup.                                                    | boolean | `false`               |

## Executable name matching

This property accepts a regular expression matched against the full executable command line, including the directory where the executable resides on the file system.
Beyla selects one process, or multiple processes with similar characteristics.
For more detailed process selection and grouping, refer to the [service discovery documentation](../service-discovery/).

When you instrument by executable name, choose a non-ambiguous name that matches one executable on the target system.
For example, if you set `BEYLA_EXECUTABLE_NAME=server` and have two processes that match the regular expression Beyla selects both.
Instead use the full application path for exact matches, for example `BEYLA_EXECUTABLE_NAME=/opt/app/server` or `BEYLA_EXECUTABLE_NAME=/server`.

If you set `executable_name`, the executable must also match any `open_port` property.

## Open port matching

This property accepts a comma-separated list of ports or port ranges. If an executable matches any of the ports Beyla selects it. For example:

```yaml
open_port: 80,443,8000-8999
```

In this example, Beyla selects any executable that opens port `80`, `443`, or any port between `8000` and `8999`.
It can select one process or multiple processes with similar characteristics.
For more detailed process selection and grouping, follow the instructions in the [service discovery documentation](../service-discovery/).

If an executable opens multiple ports, specifying one of those ports is enough for Beyla to instrument all HTTP/S and GRPC requests on all application ports.
Currently, there is no way to limit instrumentation to requests on a specific port.

If the specified port range is wide, for example `1-65535`, Beyla tries to execute all processes that own one of the ports in that range.

If you set `executable_name`, the executable must also match any `open_port` property.

## Service name and namespace

These configuration options are deprecated.

Defining these properties is equivalent to adding a `name` entry to the [`discovery.services` YAML section](../service-discovery/).
When a single instance of Beyla instruments multiple processes, they share the same service name even if they differ.
To give multiple services different names, see how to [override the service name and namespace](../service-discovery/) in the service discovery documentation.

## Trace printer formats

This option prints any instrumented trace on the standard output using one of the following formats:

| Format        | Description                    |
| ------------- | ------------------------------ |
| `disabled`    | disables the printer           |
| `text`        | prints a concise line of text  |
| `json`        | prints a compact JSON object   |
| `json_indent` | prints an indented JSON object |

## System capabilities

If you set `enforce_sys_caps` to true and the required system capabilities are missing, Beyla aborts startup and logs the missing capabilities.
If you set this option to `false`, Beyla only logs the missing capabilities.
