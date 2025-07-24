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
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------- | ---------- ||
| `shutdown_timeout`<p>`BEYLA_SHUTDOWN_TIMEOUT`</p> | Sets the timeout for a graceful shutdown                                                                                                   | string  | "10s"      |
| `log_level`<p>`BEYLA_LOG_LEVEL`</p>               | Sets process logger verbosity. Valid values: `DEBUG`, `INFO`, `WARN`, `ERROR`.                                                             | string  | `INFO`     |
| `trace_printer`<p>`BEYLA_TRACE_PRINTER`</p>       | Prints instrumented traces to the standard output in a specified format, refer to [trace printer formats](#trace-printer-formats).         | string  | `disabled` |
| `enforce_sys_caps`<p>`BEYLA_ENFORCE_SYS_CAPS`</p> | Controls how Beyla handles missing system capabilities at startup.                                                                         | boolean | `false`    |


## Trace printer formats

This option prints any instrumented trace on the standard output using one of the following formats:

- **`disabled`**: Disables the printer
- **`text`**: Prints a concise line of text
- **`json`**: Prints a compact JSON object
- **`json_indent`**: Prints an indented JSON object

## System capabilities

If you set `enforce_sys_caps` to true and the required system capabilities are missing, Beyla aborts startup and logs the missing capabilities.
If you set this option to `false`, Beyla only logs the missing capabilities.
