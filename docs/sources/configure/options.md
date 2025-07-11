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
For example, in the following command line, the `BEYLA_LOG_LEVEL` option overrides any `log_level` settings inside config.yaml:

**Config argument:**

```sh
BEYLA_LOG_LEVEL=debug beyla -config /path/to/config.yaml
```

**Config environment variable:**

```sh
BEYLA_LOG_LEVEL=debug BEYLA_CONFIG_PATH=/path/to/config.yaml beyla
```

Refer to the [example YAML configuration file](../example/) for a configuration file template.

Beyla consists of a pipeline of components that generate, transform, and export traces from HTTP and GRPC applications.
In the YAML configuration, each component has its own first-level section.

Optionally, Beyla also provides network-level metrics, refer to the [network metrics documentation](../../network/) for more information.

The following sections explain the global configuration properties that apply to the entire Beyla configuration.

For example:

```yaml
trace_printer: json
shutdown_timeout: 30s
channel_buffer_len: 33
```

| YAML<p>environment variable</p>                   | Description                                                                                                                                | Type    | Default    |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------- | ---------- |
| _(No YAML)_<p>`BEYLA_AUTO_TARGET_EXE`</p>         | Selects the process to instrument by [Glob](<https://en.wikipedia.org/wiki/Glob_(programming)>) matching against the full executable path. | string  | unset      |
| `open_port`<p>`BEYLA_OPEN_PORT`</p>               | Selects a process to instrument by open ports. Accepts comma-separated lists of ports and port ranges.                                     | string  | unset      |
| `shutdown_timeout`<p>`BEYLA_SHUTDOWN_TIMEOUT`</p> | Sets the timeout for a graceful shutdown                                                                                                   | string  | "10s"      |
| `log_level`<p>`BEYLA_LOG_LEVEL`</p>               | Sets process logger verbosity. Valid values: `DEBUG`, `INFO`, `WARN`, `ERROR`.                                                             | string  | `INFO`     |
| `trace_printer`<p>`BEYLA_TRACE_PRINTER`</p>       | Prints instrumented traces to the standard output in a specified format, refer to [trace printer formats](#trace-printer-formats).         | string  | `disabled` |
| `enforce_sys_caps`<p>`BEYLA_ENFORCE_SYS_CAPS`</p> | Controls how Beyla handles missing system capabilities at startup.                                                                         | boolean | `false`    |

## Executable name matching

This property accepts a [glob](<https://en.wikipedia.org/wiki/Glob_(programming)>) matched against the full executable command line, including the directory where the executable resides on the file system.
Beyla selects one process, or multiple processes with similar characteristics.
For more detailed process selection and grouping, refer to the [service discovery documentation](../service-discovery/).

When you instrument by executable name, choose a non-ambiguous name that matches one executable on the target system.
For example, if you set `BEYLA_AUTO_TARGET_EXE=*/server` and have two processes that match the Glob, Beyla selects both.
Instead use the full application path for exact matches, for example `BEYLA_AUTO_TARGET_EXE=/opt/app/server` or `BEYLA_AUTO_TARGET_EXE=/server`.

If you set both `BEYLA_AUTO_TARGET_EXE` and `BEYLA_OPEN_PORT` properties, Beyla selects only executables
matching both selection criteria.

## Open port matching

This property accepts a comma-separated list of ports or port ranges. If an executable matches any of the ports Beyla selects it. For example:

```
BEYLA_OPEN_PORT=80,443,8000-8999
```

In this example, Beyla selects any executable that opens port `80`, `443`, or any port between `8000` and `8999`.
It can select one process or multiple processes with similar characteristics.
For more detailed process selection and grouping, follow the instructions in the [service discovery documentation](../service-discovery/).

If an executable opens multiple ports, specifying one of those ports is enough for Beyla to instrument all HTTP/S and GRPC requests on all application ports.
Currently, there's no way to limit instrumentation to requests on a specific port.

If the specified port range is wide, for example `1-65535`, Beyla tries to execute all processes that own one of the ports in that range.

If you set both `BEYLA_AUTO_TARGET_EXE` and `BEYLA_OPEN_PORT` properties, Beyla selects only executables
matching both selection criteria.

## Service name and namespace

These configuration options are deprecated.

Defining these properties is equivalent to adding a `name` entry to the [`discovery.instrument` YAML section](../service-discovery/).
When a single instance of Beyla instruments multiple processes, they share the same service name even if they differ.
To give multiple services different names, see how to [override the service name and namespace](../service-discovery/) in the service discovery documentation.

## Trace printer formats

This option prints any instrumented trace on the standard output using one of the following formats:

- **`disabled`**: Disables the printer
- **`text`**: Prints a concise line of text
- **`json`**: Prints a compact JSON object
- **`json_indent`**: Prints an indented JSON object

## System capabilities

If you set `enforce_sys_caps` to true and the required system capabilities are missing, Beyla aborts startup and logs the missing capabilities.
If you set this option to `false`, Beyla only logs the missing capabilities.
