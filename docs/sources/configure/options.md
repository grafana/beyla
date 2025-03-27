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

Refer to the [example YAML configuration file](../example/) for a configuration file template.

Beyla consists of a pipeline of components that generate, transform, and export traces from HTTP and GRPC applications.
In the YAML configuration, each component has its own first-level section.

Optionally, Beyla also provides network-level metrics, refer to the [network metrics documentation](../../network/) for more information.

The following sections explain the global configuration properties that apply to the entire Beyla configuration:

| Lowercase YAML option<br>Uppercase environment variable option | Description                                                                                                           | Type    | Default               |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------- | --------------------- |
| `log_level`<br>`BEYLA_LOG_LEVEL`                               | Sets process logger verbosity. Valid values: `DEBUG`, `INFO`, `WARN`, `ERROR`.                                        | string  | `INFO`                |
| `trace_printer`<br>`BEYLA_TRACE_PRINTER`                       | Prints instrumented traces to stdout in a specified format, refer to [trace printer formats](#trace-printer-formats). | string  | `disabled`            |
| `enforce_sys_caps`<br>`BEYLA_ENFORCE_SYS_CAPS`                 | Controls how Beyla handles missing system capabilities at startup.                                                    | boolean | `false`               |


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
